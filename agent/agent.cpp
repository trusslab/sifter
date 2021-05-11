#include <bpf/BpfMap.h>
#include <bpf/BpfUtils.h>
#include <libbpf_android.h>
#include <linux/android/binder.h>
#include <atomic>
#include <iostream>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <vector>
#include <dirent.h>
#include <deque>
#include <map>
#include <set>
#include <bitset>
#include <sstream>
#include <signal.h>
#include <thread>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

#include "tracer_id.h"

using android::base::unique_fd;

std::ofstream g_log_stream;
std::atomic<bool> g_stop(false);
std::atomic<uint64_t> g_update_ctr;
uint64_t g_update_ts;

std::vector<std::thread> g_spawner_proc_ths;
std::string g_traced_prog;

struct rb_elem {
    struct bpf_spin_lock lock;
    uint8_t next;
    uint16_t id0[128];
    uint16_t id1[128];
};

struct u_rb_elem {
    uint8_t ctr;
    uint16_t id[256];
    u_rb_elem(): ctr(0) {
        memset(&id, 0, 256);
    }
};

#define BITSET_NR_ENTRY 3 // 1 event + 1 ioctl + 1 syscall
#define BITSET_SIZE     (BITSET_NR_ENTRY * ID_NR_SIZE)

int id_to_bitset_off(uint16_t id) {
    uint8_t hdr = ID_HDR(id);
    int ret = 0;
    switch (hdr) {
    case ID_HDR_SYSCALL: ret = ID_NR(id); break;
    case ID_HDR_IOCTL: ret = ID_NR(id) + ID_NR_SIZE; break;
    case ID_HDR_EVENT: ret = ID_NR(id) + ID_NR_SIZE*2; break;
    }
    return ret;
}

struct sifter_rb {
    int len;
    std::string name;
    unique_fd fd;
    unique_fd ctr_fd;
    std::vector<u_rb_elem> saved;
    std::map<std::deque<uint16_t>, std::bitset<BITSET_SIZE> > tbl; // [syscall seq][next syscall]

    sifter_rb(int l, std::string nm, int f, int ctr):
        len(l), name(nm), fd(android::base::unique_fd(f)),
        ctr_fd(android::base::unique_fd(ctr)) {
        saved.resize(32768);
    };

    void update_tbl(int pid, uint8_t ctr, rb_elem &rb, bool missing_events) {
        bool first_half = (ctr%2 == 0);
        uint8_t dst_start = first_half? 0 : 128;
        uint16_t *src_ptr = first_half? rb.id0 : rb.id1;
        memcpy(&saved[pid].id[dst_start], src_ptr, 128);

        std::deque<uint16_t> seq;
        uint8_t start = missing_events? dst_start : dst_start-len;
        for (int i = 0; i < len; i++) {
            uint8_t off = start+i;
            seq.push_back(saved[pid].id[off]);
        }
        for (int i = 0; i < 127-len; i++) {
            uint8_t off = start+len+i;
            uint16_t next = saved[pid].id[off];
            if (tbl.find(seq) != tbl.end()) {
                if (!tbl[seq].test(id_to_bitset_off(next))) {
                    printf("r0\n");
                    g_update_ctr++;
                }
                tbl[seq].set(id_to_bitset_off(next));
            } else {
                printf("r1\n");
                g_update_ctr++;
                tbl[seq] = std::bitset<BITSET_SIZE>(0);
                tbl[seq].set(id_to_bitset_off(next));
            }
            if (next == ID_EVENT_END)
                break;
            seq.pop_front();
            seq.push_back(next);
        }
    };
};

struct sifter_lut {
    int type;
    std::string name;
    unique_fd fd;
    std::vector<uint64_t> val;

    sifter_lut(int t, std::string nm, int size, int f):
        type(t), name(nm), fd(android::base::unique_fd(f)) {
        val.resize(size);
    };
};

struct sifter_map {
    int type;
    std::string name;
    unique_fd fd;
    std::vector<uint64_t> val;

    sifter_map(int t, std::string nm, int size, int f):
        type(t), name(nm), fd(android::base::unique_fd(f)) {
        val.resize(size);
    };
};

struct sifter_prog {
    int type;
    std::string event;
    std::string entry;
    unique_fd fd;

    sifter_prog(int t, std::string ev, std::string en, int f):
        type(t), event(ev), entry(en), fd(android::base::unique_fd(f)) {};
};

int proc_bitness(std::vector<int> &proc_bitness, int pid, int verbose) {
    int bitness = proc_bitness[pid];
    if (bitness != -1)
        return bitness;

    std::ifstream ifs;
    int len = 0;
    char target[256];
    std::string file = "/proc/" + std::to_string(pid) + "/exe";
    len = readlink(file.c_str(), target, sizeof(target)-1);

    target[len] = '\0';
    //std::cout << "check " << target << "\n";

    //Determine Zygote processes bitness by name: app_process32/64
    if (len > 2) {
        if (target[len-2] == '3' && target[len-1] == '2')
            bitness = 32;
        if (target[len-2] == '6' && target[len-1] == '4')
            bitness = 64;
        if (bitness != -1) {
            proc_bitness[pid] = bitness;
            return bitness;
        }
    }

    //Determine processes bitness by ELF header magic number
    char magic[5] = {};
    ifs.open(target, std::ios::binary);
    if (!ifs) {
        if (verbose > 3)
            std::cout << "Error checking bitness via ELF magic: cannot open "
                    << target << " (" << pid << ")\n";
    } else {
        ifs.read(magic, 5);
        if (*(uint32_t *)(magic) == 0x464c457f) {
            if (magic[4] == 1) {
                bitness = 32;
            } else if (magic[4] == 2) {
                bitness = 64;
            } else if (verbose > 3){
                std::cout << "Error checking bitness via ELF header: "
                        << target << " (" << pid << ") invalid EI_CLASS "
                        << std::hex << (uint32_t)magic[4] << std::dec << "\n";
            }
        } else if (verbose > 3) {
            std::cout << "Error checking bitness via ELF header: "
                        << target << " (" << pid << ") invalid ELF magic number\n";
        }
    }
    ifs.close();
    proc_bitness[pid] = bitness;
    return bitness;
}

class sifter_tracer {
private:
    int m_init;
    int m_verbose;
    int m_bitness;
    std::string m_name;
    std::vector<sifter_prog> m_progs;
    std::vector<sifter_map> m_maps;
    std::vector<sifter_lut> m_luts;
    std::vector<sifter_rb> m_rbs;
    std::vector<std::thread *> m_rbs_update_threads;
    std::vector<int> m_proc_bitness;
    std::set<int> m_ignored_pids;
    std::vector<std::string> m_target_prog_comm_list;
    unique_fd m_target_prog_comm_map_fd;
    int m_min_pid;
    bool m_rbs_update_start;

    void update_rbs_thread() {
        m_min_pid = gettid();
        while (m_rbs_update_start) {
            for (auto &rb : m_rbs) {
                auto begin = std::chrono::steady_clock::now();
                for (int p = m_min_pid; p < 32768; p++) {
                    if (m_ignored_pids.find(p) != m_ignored_pids.end())
                        continue;

                    uint8_t ctr;
                    android::bpf::findMapEntry(rb.ctr_fd, &p, &ctr);
                    uint8_t last_ctr = rb.saved[p].ctr;
                    if (ctr != last_ctr
                        && proc_bitness(m_proc_bitness, p, m_verbose) == m_bitness) {
                        bool missing_events = (ctr != last_ctr+1);
                        if (m_verbose > 0) {
                            if (missing_events)
                                std::cout << "Update events pid[" << p << "] "
                                    << (int)ctr << " - " << (int)last_ctr << "\n";
                            else
                                std::cout << "Update events pid[" << p << "] "
                                    << (int)ctr <<"\n";
                        }
                        rb_elem rbp;
                        android::bpf::findMapEntry(rb.fd, &p, &rbp);
                        rb.saved[p].ctr = ctr;
                        rb.update_tbl(p, ctr, rbp, missing_events);
                    }
                }
                auto end = std::chrono::steady_clock::now();
                std::chrono::duration<float> scan_time = end - begin;
                uint32_t dur_ms = std::chrono::duration_cast<std::chrono::milliseconds>(scan_time).count();
                usleep(1000000-dur_ms*1000);
                g_update_ts++;
                g_log_stream << g_update_ts << "," << g_update_ctr << "\n";
                g_log_stream.flush();
                if (m_verbose > 1) {
                    std::cout << "finish seq update in " << dur_ms << " ms, #update = " << g_update_ctr << "\n";
                }
            }
        }
    }

public:
    size_t map_num() {
        return m_maps.size();
    }

    size_t rb_num() {
        return m_rbs.size();
    }

    int add_prog(int type, std::string event, std::string entry) {
        std::string probe_name;
        switch (type) {
            case 0: probe_name = std::string("_kretprobe_") + entry; break;
            case 1: probe_name = std::string("_kprobe_") + entry; break;
            case 2: probe_name = std::string("_tracepoint_") + event + "_" + entry; break;
            case 3: probe_name = std::string("_kprobe_") + event; break;
            case 4: probe_name = std::string("_kprobe_") + event; break;
        }
        std::string path = "/sys/fs/bpf/prog_" + m_name + probe_name;
        if (access(path.c_str(), 0) != 0) {
            int ret = android::bpf::loadProg(path.c_str());
            if (ret) {
                std::cerr << path << " does not exist and attempt to load it failed\n";
                return ret;
            }
        }
        int fd = bpf_obj_get(path.c_str());
        if (fd != -1)
            m_progs.push_back(sifter_prog(type, event, entry, fd));
        return fd;
    }

    int add_map(int type, std::string map) {
        std::string path = "/sys/fs/bpf/map_" + m_name + "_" + map;
        int fd = bpf_obj_get(path.c_str());
        if (fd != -1)
            m_maps.push_back(sifter_map(type, map, 2, fd));
        return fd;
    }

    int add_lut(int type, std::string map, std::vector<uint64_t> &val) {
        std::string path = "/sys/fs/bpf/map_" + m_name + "_" + map;
        int fd = bpf_obj_get(path.c_str());
        if (fd != -1)
            m_luts.push_back(sifter_lut(type, map, val.size(), fd));
        for (int i = 0; i < val.size(); i++) {
            android::bpf::writeToMapEntry(m_luts.back().fd, &i, &val[i], BPF_ANY);
        }
        return fd;
    }

    int add_rb(int len, std::string map) {
        std::string path = "/sys/fs/bpf/map_" + m_name + "_" + map;
        int fd = bpf_obj_get(path.c_str());
        path += "_ctr";
        int ctr_fd = bpf_obj_get(path.c_str());
        if (fd != -1 && ctr_fd != -1) {
            m_rbs.push_back(sifter_rb(len, map, fd, ctr_fd));
            return fd;
        }
        return -1;
    }

    int attach_prog() {
        for (auto &p : m_progs) {
            if (p.type == 0 || p.type == 1) {
                bpf_probe_attach_type type = p.type == 1? BPF_PROBE_ENTRY : BPF_PROBE_RETURN;
                int ret = bpf_attach_kprobe(p.fd, type, p.event.c_str(), p.entry.c_str(), 0);
                if (ret < 0) {
                    std::cout << "bpf_attach_kprobe return " << ret << " " << errno << "\n";
                    return -1;
                }
            } else if (p.type == 3 || p.type == 4) {
                bpf_probe_attach_type type = p.type == 4? BPF_PROBE_ENTRY : BPF_PROBE_RETURN;
                int delim_pos = p.entry.find(":");
                if (delim_pos == std::string::npos) {
                    std::cout << "bpf_attach_uprobe entry should be <path>:<offset>\n";
                    return -1;
                }
                std::string path = p.entry.substr(0, delim_pos);
                std::string offset = p.entry.substr(delim_pos+1);
                size_t pos = 0;
                uint64_t off = std::stoull(offset.c_str(), &pos, 16);
                if (pos != offset.size()) {
                    std::cout << "bpf_attach_uprobe offset " << offset << "is not a valid number\n";
                    return -1;
                }

                int ret = bpf_attach_uprobe(p.fd, type, p.event.c_str(), path.c_str(), off, -1);
                if (ret < 0) {
                    std::cout << "bpf_attach_uprobe return " << ret << " " << errno << "\n";
                    return -1;
                }
            } else if (p.type == 2) {
                int ret = bpf_attach_tracepoint(p.fd, p.event.c_str(), p.entry.c_str());
                if (ret < 0) {
                    std::cout << "bpf_attach_tracepoint return " << ret << " " << errno << "\n";
                    return -1;
                }
            }
        }
        return 0;
    }

    int detach_prog() {
        for (auto &p : m_progs) {
            if (p.type == 0 || p.type == 1) {
                int ret = bpf_detach_kprobe(p.event.c_str());
                if (ret < 0) {
                    std::cout << "bpf_detach_kprobe return " << ret << " " << errno << "\n";
                    return -1;
                }
            } else if (p.type == 2) {
                int ret = bpf_detach_tracepoint(p.event.c_str(), p.entry.c_str());
                if (ret < 0) {
                    std::cout << "bpf_detach_tracepoint return " << ret << " " << errno << "\n";
                    return -1;
                }
            }
        }
        return 0;
    }

    void print_rbs() {
        for (auto &rb : m_rbs) {
            for (auto &entry : rb.tbl) {
                for (auto it : entry.first)
                    std::cout << std::setw(5) << it << " ";
                std::cout << "| ";
                for (int i = 0; i < ID_NR_SIZE; i++) {
                    if (entry.second[i])
                        std::cout << std::setw(5) << i << " ";
                }
                for (int i = 0; i < ID_NR_SIZE; i++) {
                    if (entry.second[ID_NR_SIZE+i])
                        std::cout << std::setw(5) << ((ID_HDR_IOCTL << ID_HDR_SHIFT) | i) << " ";
                }
                for (int i = 0; i < ID_NR_SIZE; i++) {
                    if (entry.second[2*ID_NR_SIZE+i])
                        std::cout << std::setw(5) << ((ID_HDR_EVENT << ID_HDR_SHIFT) | i) << " ";
                }
                std::cout << "\n";
            }
            std::cout << "Total: " << rb.tbl.size() << " sequences" << "\n";
        }
    }

    void dump_rbs(std::string file) {
        std::ofstream ofs(file, std::ofstream::app);
        for (auto &rb : m_rbs) {
            ofs << "r " << rb.tbl.size() << "\n";
            for (auto &entry : rb.tbl) {
                ofs << std::setw(3) << entry.first.size()
                        << std::setw(4) << entry.second.count() << " ";
                for (auto it : entry.first)
                    ofs << std::setw(5) << it << " ";
                for (int i = 0; i < ID_NR_SIZE; i++) {
                    if (entry.second[i])
                        ofs << std::setw(5) << i << " ";
                }
                for (int i = 0; i < ID_NR_SIZE; i++) {
                    if (entry.second[ID_NR_SIZE+i])
                        ofs << std::setw(5) << ((ID_HDR_IOCTL << ID_HDR_SHIFT) | i) << " ";
                }
                for (int i = 0; i < ID_NR_SIZE; i++) {
                    if (entry.second[2*ID_NR_SIZE+i])
                        ofs << std::setw(5) << ((ID_HDR_EVENT << ID_HDR_SHIFT) | i) << " ";
                }
                ofs << "\n";
            }
        }
    }

    void recover_rbs(std::string file) {
        std::ifstream ifs(file);

        if (ifs) {
            for (auto &m : m_rbs) {
                char c;
                while (ifs >> c && c != 'r') {}

                uint64_t seqs_size, seq_size, next_size, v;
                ifs >> seqs_size;
                for (int j = 0; j < seqs_size; j++) {
                    std::deque<uint16_t> seq;
                    std::bitset<BITSET_SIZE> next;
                    ifs >> seq_size >> next_size;
                    seq.resize(seq_size);
                    for (int i = 0; i < seq_size; i++) {
                        ifs >> seq[i];
                    }
                    for (int i = 0; i < next_size; i++) {
                        ifs >> v;
                        next.set(id_to_bitset_off(v));
                    }
                    m.tbl[seq] = next;
                }
            }
        }
    }

    void print_maps() {
        for (auto &m : m_maps) {
            int size = m.val.size();
            std::cout << m.name << " [";
            for (int i = 0; i < size; i++) {
                android::bpf::findMapEntry(m.fd, &i, &m.val[i]);
                std::cout << m.val[i];
                if (i != size-1)
                    std::cout << ", ";
            }
            std::cout << "]\n";
        }
    }

    void dump_maps(std::string file) {
        if (m_maps.empty())
            return;

        std::ofstream ofs(file, std::ofstream::app);
        ofs << "m\n";
        for (auto &m : m_maps) {
            for (auto v : m.val)
                ofs << v << " ";
            ofs << "\n";
        }
    }

    void recover_maps(std::string file) {
        std::ifstream ifs(file);

        if (!ifs) {
            for (auto &m: m_maps) {
                switch (m.type) {
                    case 0:
                        m.val[0] = (uint64_t)-1;
                        m.val[1] = 0;
                        break;
                    case 1:
                        m.val[0] = 0;
                        m.val[1] = 0;
                        break;
                }
            }
        } else {
            char c;
            while (ifs >> c && c != 'm') {}

            for (auto &m : m_maps) {
                for (auto &v : m.val)
                    ifs >> v;
            }
        }

    }

    void update_maps() {
        for (auto &m : m_maps) {
            int size = m.val.size();
            std::vector<uint64_t> val(size);
            for (int i = 0; i < size; i++)
                android::bpf::findMapEntry(m.fd, &i, &val[i]);

            switch (m.type) {
                case 0:
                    if (val[0] < m.val[0]) {
                        printf("m0\n");
                        g_update_ctr++;
                        m.val[0] = val[0];
                    }
                    if (val[1] > m.val[1]) {
                        printf("m0\n");
                        g_update_ctr++;
                        m.val[1] = val[1];
                    }
                    break;
                case 1:
                    if (~m.val[0] & val[0]) {
                        printf("m1\n");
                        g_update_ctr++;
                    }
                    if (~m.val[1] & val[1]) {
                        printf("m1\n");
                        g_update_ctr++;
                    }
                    m.val[0] |= val[0];
                    m.val[1] |= val[1];
                    break;
            }
        }
    }

    void start_update_rbs() {
        m_ignored_pids.insert(gettid());
        m_rbs_update_start = 1;
        std::thread *th = new std::thread(&sifter_tracer::update_rbs_thread, this);
        m_rbs_update_threads.push_back(th);
    }

    void stop_update_rbs() {
        m_rbs_update_start = 0;
        for (auto &th : m_rbs_update_threads) {
            th->join();
        }
    }
    
    operator bool() const {
        return m_init == 1;
    }

    //sifter_tracer(): m_init(0) {};

    sifter_tracer(std::string file, int verbose=0): m_init(0), m_verbose(verbose) {
        std::ifstream ifs(file);

        if (!ifs) {
            std::cerr << "Failed to parse configuration. File \"" << file
                << "\" does not exist\n";
            return;
        }

        ifs >> m_name >> m_bitness;
        char cfg_type;
        while (ifs >> cfg_type) {
            switch (cfg_type) {
                case 'p': {
                    int type;
                    std::string event, entry;
                    ifs >> type >> event >> entry;
                    if (add_prog(type, event, entry) == -1) {
                        std::cerr << "Failed to add prog (type:"
                            << type << ", " << event << ", " << entry << ")\n";
                        return;
                    }

                    if (m_verbose > 0)
                        std::cout << "Added prog (type:"
                            << type << ", " << event << ", " << entry << ")\n";
                    break;
                }
                case 'm': {
                    int type;
                    std::string name;
                    ifs >> type >> name;
                    if (add_map(type, name) == -1) {
                        std::cerr << "Failed to add map (type:"
                            << type << ", name:" << name << ")\n";
                        return;
                    }

                    if (m_verbose > 0)
                        std::cout << "Added map (type:"
                            << type << ", name:" << name << ")\n";
                    break;
                }
                case 'l': {
                    int type, size;
                    int i = 0;
                    std::string name;
                    ifs >> type >> name >> size;
                    std::vector<uint64_t> vals;
                    vals.resize(size);
                    while (i < size && ifs >> vals[i++]) {}
                    if (i != size) {
                        std::cerr << "Failed to add lookup table (type:"
                            << type << ", name:" << name << ", size:" << size
                            << "). Too few entries (" << i-1 << ")\n";
                        return;
                    }

                    if (add_lut(type, name, vals) == -1) {
                        std::cerr << "Failed to add lookup table (type:"
                            << type << ", name:" << name << ", size:" << size
                            << "). errno(" << errno << ")\n";
                        return;
                    }

                    if (m_verbose > 0)
                        std::cout << "Added lookup table (type:"
                            << type << ", name:" << name << ", size:" << size << ")\n";
                    break;
                }
                case 'r': {
                    int length;
                    std::string name;
                    ifs >> length >> name;
                    if (add_rb(length, name) == -1) {
                        std::cerr << "Failed to add ringbuffer (name:" << name << ")\n";
                        return;
                    }
                    if (m_verbose > 0)
                        std::cout << "Added ringbuffer (name:" << name << ")\n";
                    break;
                }
                default:
                    std::cerr << "Failed to parse configuration. Invalid cfg entry \'"
                        << cfg_type << "\'\n";
                    return;
            }
        }
        m_proc_bitness.resize(32768, -1);

        g_update_ctr = 0;
        g_update_ts = 0;
        std::stringstream ss;
        std::time_t t = std::time(nullptr);
        ss << "tracing_agent_" << t << ".log";
        g_log_stream.open(ss.str());
        if (!g_log_stream) {
            std::cerr << "Failed to open update log\n";
            return;
        }

        std::string path = "/sys/fs/bpf/map_" + m_name + "_tracer_target_prog_comm_map";
        int target_prog_comm_map_fd = bpf_obj_get(path.c_str());
        if (target_prog_comm_map_fd != -1)
            m_target_prog_comm_map_fd = unique_fd(target_prog_comm_map_fd);

        uint32_t dummy_val = 1;
        for (auto s : m_target_prog_comm_list) {
            char target_prog_comm[16] = {};
            strncpy(target_prog_comm, s.c_str(), 16);
            android::bpf::writeToMapEntry(m_target_prog_comm_map_fd,
                    target_prog_comm, &dummy_val, BPF_ANY);
        }

        m_init = 1;
    }

    ~sifter_tracer() {
        m_init = 0;
        stop_update_rbs();
        detach_prog();
    }

};

void signal_handler(int s) {
    (void)s;
    g_stop.store(true);
}

std::string get_proc_name(int pid) {
    std::ifstream ifs;
    std::string proc_name;
    std::string proc_name_path = "/proc/" + std::to_string(pid) + "/cmdline";
    ifs.open(proc_name_path);
    std::getline(ifs, proc_name);
    return proc_name.substr(0, proc_name.find('\0'));
}

void get_proc_spawners(std::vector<int> &proc_spawners) {
    DIR *dir;
    if ((dir = opendir("/proc/")) == NULL) {
        std::cerr << "Failed to open /proc/, which is needed to monitor processes of interest\n";
        return;
    }

    const char *proc_spawners_name[] = {"-/system/bin/sh", "zygote", "zygote64"};
    struct dirent *de;
    while ((de = readdir(dir)) != NULL) {
        char *p;
        long pid = strtol(de->d_name, &p, 10);
        if (*p)
            continue;

        std::string proc_name = get_proc_name(pid);
        for (int i = 0; i < 3; i++) {
            if (proc_name.compare(proc_spawners_name[i]) == 0) {
                proc_spawners.push_back(pid);
                std::cout << "Monitoring process spawners [" << pid << "] " << proc_name << "\n";
                break;
            }
        }
    }
    closedir(dir);

    return;
}

std::string ptrace_read_str(int pid, uint64_t addr) {
    union u {
        uint32_t val;
        char chars[4];
    } data;
    std::cout << "addr: "<< std::hex << addr << "\n";
    char path[256];
    for (int i = 0; i < 256; i+=4) {
        data.val = ptrace(PTRACE_PEEKDATA, pid, addr+i*4 , NULL);
        std::cout << std::hex << data.val << std::dec << " ";
        memcpy(&path[i], data.chars, 4);
        if (data.chars[0] == 0 || data.chars[1] == 0 || data.chars[2] == 0 || data.chars[3] == 0)
            break;
    }
    return std::string(path);
}

bool loop_until_identified(int pid, std::string prog_name) {
    int ret = 0;
    int status = 0;
    unsigned long data = 0;
    struct user_regs_struct regs;
    struct iovec io;
    io.iov_base = &regs;
    io.iov_len = sizeof(regs);
    while (1) {
        std::cout << "[" << pid << "] waitpid\n";
        waitpid(pid, &status, 0);
        std::cout << "[" << pid << "] status changed: " << std::hex << status << std::dec<<"\n";
        if (WIFEXITED(status)) {
            std::cout << "[" << pid << "] exit\n";
            break;
        } else if (status >> 8 == (SIGTRAP | (PTRACE_EVENT_FORK<<8))) {
            ret = ptrace(PTRACE_GETEVENTMSG, pid, NULL, &data);
            std::cout << "[" << pid << "] fork [" << data << "] " << "\n";
        } else if (status >> 8 == (SIGTRAP | (PTRACE_EVENT_VFORK<<8))) {
            ret = ptrace(PTRACE_GETEVENTMSG, pid, NULL, &data);
            std::cout << "[" << pid << "] vfork [" << data << "] " << "\n";
        } else if (status >> 8 == (SIGTRAP | (PTRACE_EVENT_CLONE<<8))) {
            ret = ptrace(PTRACE_GETEVENTMSG, pid, NULL, &data);
            std::cout << "[" << pid << "] clone [" << data << "]\n";
        } else if (status >> 8 == (SIGTRAP | (PTRACE_EVENT_EXEC<<8))) {
            std::string new_prog_name = get_proc_name(pid);
            std::cout << "[" << pid << "] execve " << new_prog_name << "\n";
            if (prog_name.compare(new_prog_name) == 0)
                return true;
            else
                return false;
        }
        std::cout << "[" << pid << "] cont \n";
        ptrace(PTRACE_CONT, pid, NULL, NULL);

        if (g_stop.load()) break;
    };

    return false;
}

void proc_spawner_monitor_th(int spwaner_pid) {
    int ret = 0;
    int status = 0;
    unsigned long data = 0;
    ret = ptrace(PTRACE_ATTACH, spwaner_pid, NULL, NULL);
    if (ret != 0) {
        std::cerr << "[" << spwaner_pid << "] ptrace attach error: " << strerror(errno) << "\n";
        return;
    }
    waitpid(spwaner_pid, &status, 0);

    data = PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACEEXEC;
    ret = ptrace(PTRACE_SETOPTIONS, spwaner_pid, NULL, data);
    if (ret != 0) {
        std::cerr << "[" << spwaner_pid << "] ptrace set option error: " << strerror(errno) << "\n";
        return;
    }
    ptrace(PTRACE_CONT, spwaner_pid, NULL, NULL);

    while (1) {
        std::cout << "[" << spwaner_pid << "] waitpid\n";
        waitpid(spwaner_pid, &status, 0);
        std::cout << "[" << spwaner_pid << "] status changed: " << status << "\n";
        if (WIFEXITED(status)) {
            std::cout << "[" << spwaner_pid << "] exit\n";
            break;
        } else if (status >> 8 == (SIGTRAP | (PTRACE_EVENT_FORK<<8))) {
            ret = ptrace(PTRACE_GETEVENTMSG, spwaner_pid, NULL, &data);
            std::cout << "[" << spwaner_pid << "] fork [" << data << "] " << "\n";
            loop_until_identified(data, g_traced_prog);
            ptrace(PTRACE_DETACH, data, NULL, NULL);
        } else if (status >> 8 == (SIGTRAP | (PTRACE_EVENT_VFORK<<8))) {
            ret = ptrace(PTRACE_GETEVENTMSG, spwaner_pid, NULL, &data);
            std::cout << "[" << spwaner_pid << "] vfork [" << data << "] " << "\n";
        } else if (status >> 8 == (SIGTRAP | (PTRACE_EVENT_CLONE<<8))) {
            ret = ptrace(PTRACE_GETEVENTMSG, spwaner_pid, NULL, &data);
            std::cout << "[" << spwaner_pid << "] clone [" << data << "] " << "\n";
        }
        std::cout << "[" << spwaner_pid << "] cont \n";
        ptrace(PTRACE_CONT, spwaner_pid, NULL, NULL);

        if (g_stop.load()) break;
    };

    ptrace(PTRACE_DETACH, spwaner_pid, NULL, NULL);
    return;
}

int main(int argc, char *argv[]) {
    bool recover = true;
    bool manual_mode = false;
    int log_interval = 1;
    int verbose = 0;
    char empty_string[] = "";
    char *config_file = empty_string;
    char *log_file = empty_string;
    char *traced_prog = empty_string;

    int opt;
    while ((opt = getopt (argc, argv, "hmi:v:c:r:o:p:")) != -1) {
        switch (opt) {
            case 'h':
                std::cout << "Sifter agent\n";
                std::cout << "Options\n";
                std::cout << "-c config   : agent configuration file [required]\n";
                std::cout << "-o output   : maps logging output file [required except manual mode]\n";
                std::cout << "-p program  : program to trace [required]\n";
                std::cout << "-m          : use manual mode\n";
                std::cout << "-i interval : maps logging interval in seconds [default=10]\n";
                std::cout << "-r recover  : recover from log when start [default=1 (enabled)]\n";
                std::cout << "-v verbose  : verbosity [default=0]\n";
                std::cout << "-h          : helps\n";
                return 0;
            case 'm': manual_mode = true; break;
            case 'i': log_interval = atoi(optarg); break;
            case 'v': verbose = atoi(optarg); break;
            case 'c': config_file = optarg; break;
            case 'r': recover = atoi(optarg) > 0; break;
            case 'o': log_file = optarg; break;
            case 'p': traced_prog = optarg; break;
            case '?':
                if (optopt == 'c')
                    fprintf(stderr, "Option -%c requires an argument.\n", optopt);
                else if (isprint (optopt))
                    fprintf(stderr, "Unknown option `-%c'.\n", optopt);
                else
                    fprintf(stderr, "Unknown option character `\\x%x'.\n", optopt);
                return 1;
            default: abort();
        }
    }

//    g_traced_prog = std::string(traced_prog);
//    std::vector<int> proc_spawners;
//    get_proc_spawners(proc_spawners);
//    for (auto pid : proc_spawners) {
//        std::thread th(proc_spawner_monitor_th, pid);
//        g_spawner_proc_ths.push_back(std::move(th));
//    }

    struct sigaction sa = {};
    sa.sa_handler = signal_handler;
    sigfillset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);

    sifter_tracer tracer(config_file, verbose);

    if (!tracer) {
        std::cout << "Failed to create tracer\n";
        return 1;
    }

    tracer.attach_prog();

    if (recover) {
        if (tracer.rb_num() > 0)
            tracer.recover_rbs(log_file);
        if (tracer.map_num() > 0)
            tracer.recover_maps(log_file);
    }

    if (tracer.rb_num() > 0) {
        tracer.start_update_rbs();
    }

    if (manual_mode) {
        std::cout << "\nPress enter to stop...\n";
        std::cin.get();
        tracer.print_maps();
        tracer.print_rbs();
        tracer.stop_update_rbs();
        return 0;
    }

    std::string tmp_file = std::string(log_file) + ".tmp";
    while (1) {
        tracer.update_maps();
        tracer.dump_maps(tmp_file);
        tracer.dump_rbs(tmp_file);
        std::rename(tmp_file.c_str(), log_file);
        std::remove(tmp_file.c_str());
        sleep(log_interval);
        if (g_stop.load()) break;
    }
    return 0;
}
