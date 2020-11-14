#include <bpf/BpfMap.h>
#include <bpf/BpfUtils.h>
#include <libbpf_android.h>
#include <linux/android/binder.h>
#include <iostream>
#include <cstdio>
#include <fstream>
#include <vector>
#include <deque>
#include <map>
#include <set>
#include <bitset>
#include <sstream>
#include <thread>
#include <unistd.h>

using android::base::unique_fd;


struct rb_elem {
    struct bpf_spin_lock lock;
    uint8_t next;
    uint16_t id0[128];
    uint16_t id1[128];
};

struct u_rb_elem {
    uint8_t ctr;
    uint16_t id[256];
};

struct sifter_rb {
    int len;
    std::string name;
    unique_fd fd;
    unique_fd ctr_fd;
    std::vector<u_rb_elem> saved;
//    std::vector<std::map<std::deque<uint16_t>, std::bitset<65536> > > tbl;
    std::map<std::deque<uint16_t>, std::bitset<65536> > tbl;
    sifter_rb(int l, std::string nm, int f, int ctr):
        len(l), name(nm), fd(android::base::unique_fd(f)),
        ctr_fd(android::base::unique_fd(ctr)) {
//        tbl.resize(32768);
        saved.resize(32768);
    };
    void update_tbl(int pid, uint8_t ctr, rb_elem rb, bool missing_events) {
        bool first_half = (ctr%2 == 0);
        uint8_t dst_start = first_half? 0 : 128;
        uint16_t *src_ptr = first_half? rb.id0 : rb.id1;
        memcpy(&saved[pid].id[dst_start], src_ptr, 256);

        std::deque<uint16_t> seq;
        uint8_t start = missing_events? dst_start : dst_start-len;
        for (int i = start; i <= start+len-1; i++)
            seq.push_back(saved[pid].id[i]);
        for (int i = start+len; i < start+127; i++) {
            uint16_t next = saved[pid].id[i];
            if (tbl.find(seq) != tbl.end())
                tbl[seq].set(next);
            else
                tbl[seq] = std::bitset<65536>(next);
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

class sifter_tracer {
private:
    int m_init;
    int m_verbose;
    std::string m_name;
    std::vector<sifter_prog> m_progs;
    std::vector<sifter_map> m_maps;
    std::vector<sifter_lut> m_luts;
    std::vector<sifter_rb> m_rbs;
    std::vector<std::thread *> m_rbs_update_threads;
    std::set<int> m_ignored_pids;
    bool m_rbs_update_start;

    void update_rbs_thread() {
        m_ignored_pids.insert(gettid());
        while (m_rbs_update_start) {
            for (auto &rb : m_rbs) {
                for (int p = 0; p < 32768; p++) {
                    if (m_ignored_pids.find(p) != m_ignored_pids.end())
                        continue;

                    uint8_t ctr;
                    android::bpf::findMapEntry(rb.ctr_fd, &p, &ctr);
                    uint8_t last_ctr = rb.saved[p].ctr;
                    if (ctr != last_ctr) {
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
        std::string probe_name;// = is_entry? "_kprobe_" : "_kretporbe_";
        switch (type) {
            case 0: probe_name = std::string("_kretprobe_") + entry; break;
            case 1: probe_name = std::string("_kprobe_") + entry; break;
            case 2: probe_name = std::string("_tracepoint_") + event + "_" + entry; break;
        }
        std::string path = "/sys/fs/bpf/prog_" + m_name + probe_name;
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

    void print_rbs() {
        for (auto &rb : m_rbs) {
            for (auto &entry : rb.tbl) {
                for (auto it : entry.first)
                    std::cout << std::setw(4) << it << " ";
                std::cout << "| ";
                for (int i = 0; i < 65536; i++)
                    if (entry.second[i])
                        std::cout << std::setw(4) << i << " ";
                std::cout << "\n";
            }
            std::cout << "Total: " << rb.tbl.size() << " sequences" << "\n";
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
        std::ofstream ofs(file.c_str());
        for (auto &m : m_maps) {
            for (auto v : m.val)
                ofs << v << " ";
            ofs << "\n";
        }
    }

    void recover_maps(std::string file) {
        std::ifstream ifs(file.c_str());

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
                    if (val[0] < m.val[0]) m.val[0] = val[0];
                    if (val[1] > m.val[1]) m.val[1] = val[1];
                    break;
                case 1:
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

    sifter_tracer(): m_init(0) {};

    sifter_tracer(std::string file, int verbose=0): m_init(0), m_verbose(verbose) {
        std::ifstream ifs(file);

        if (!ifs) {
            std::cerr << "Failed to parse configuration. " << file
                << " does not exist\n";
            return;
        }

        ifs >> m_name;
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
        m_init = 1;
    }

};

int main(int argc, char *argv[]) {
    bool manual_mode = false;
    int log_interval = 10;
    int verbose = 0;
    char *config_file = nullptr;
    char *log_file = nullptr;

    int opt;
    while ((opt = getopt (argc, argv, "hmi:v:c:o:")) != -1) {
        switch (opt) {
            case 'h':
                std::cout << "Sifter agent\n";
                std::cout << "Options\n";
                std::cout << "-c config   : agent configuration file [required]\n";
                std::cout << "-m          : read maps\n";
                std::cout << "-i interval : maps logging interval in seconds [default=10]\n";
                std::cout << "-o output   : maps logging output file\n";
                std::cout << "-v verbose  : verbosity\n";
                std::cout << "-h          : helps\n";
                return 0;
            case 'm': manual_mode = true; break;
            case 'i': log_interval = atoi(optarg); break;
            case 'v': verbose = atoi(optarg); break;
            case 'c': config_file = optarg; break;
            case 'o': log_file = optarg; break;
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

    sifter_tracer tracer(config_file, verbose);

    if (!tracer) {
        std::cout << "Failed to create tracer\n";
        return 1;
    }

    tracer.attach_prog();

    if (manual_mode) {
        std::cout << "\nPress enter to read map values...\n";
        std::cin.get();
        tracer.print_maps();
        return 0;
    }

    if (tracer.rb_num() > 0) {
        tracer.start_update_rbs();
        std::cout << "\nPress enter to read seq values...\n";
        std::cin.get();
        tracer.print_rbs();
        tracer.stop_update_rbs();
        return 0;
    }

    if (tracer.map_num() > 0) {
        tracer.recover_maps(log_file);
        std::string tmp_file = std::string(log_file) + ".tmp";
        while (1) {
            tracer.update_maps();
            tracer.dump_maps(tmp_file);
            std::rename(tmp_file.c_str(), log_file);
            sleep(log_interval);
        }
    }

}
