#include <bpf/BpfMap.h>
#include <bpf/BpfUtils.h>
#include <libbpf_android.h>
#include <linux/android/binder.h>
#include <iostream>
#include <cstdio>
#include <fstream>
#include <vector>
#include <sstream>
#include <unistd.h>

using android::base::unique_fd;

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
    bool is_entry;
    std::string event;
    std::string entry;
    unique_fd fd;
    sifter_prog(bool is_e, std::string ev, std::string en, int f):
        is_entry(is_e), event(ev), entry(en), fd(android::base::unique_fd(f)) {};
};

class sifter_tracer {
    int m_init;
    std::string m_name;
    std::vector<sifter_prog> m_progs;
    std::vector<sifter_map> m_maps;

public:
    int add_prog(bool is_entry, std::string event, std::string entry) {
        std::string probe = is_entry? "_kprobe_" : "_kretporbe_";
        std::string path = "/sys/fs/bpf/prog_" + m_name + probe + entry;
        int fd = bpf_obj_get(path.c_str());
        if (fd != -1)
            m_progs.push_back(sifter_prog(is_entry, event, entry, fd));
        return fd;
    };

    int add_map(int type, std::string map) {
        std::string path = "/sys/fs/bpf/map_" + m_name + "_" + map;
        int fd = bpf_obj_get(path.c_str());
        if (fd != -1)
            m_maps.push_back(sifter_map(type, map, 2, fd));
        return fd;
    };

    int attach_prog() {
        for (auto &p : m_progs) {
            bpf_probe_attach_type type = p.is_entry? BPF_PROBE_ENTRY : BPF_PROBE_RETURN;
            int ret = bpf_attach_kprobe(p.fd, type, p.event.c_str(), p.entry.c_str(), 0);
            if (ret < 0) {
                std::cout << "bpf_attach_kprobe return " << ret << " " << errno << "\n";
                return -1;
            }
        }
        return 0;
    };

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
    };

    void dump_maps(std::string file) {
        std::ofstream ofs(file.c_str());
        for (auto &m : m_maps) {
            for (auto v : m.val)
                ofs << v << " ";
            ofs << "\n";
        }
    };

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
            for (auto &m: m_maps) {
                for (auto &v : m.val)
                    ifs >> v;
            }
        }

    };

    void update_maps() {
        for (auto &m: m_maps) {
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
    };

    operator bool() const {
        return m_init == 1;
    };

    sifter_tracer(): m_init(0) {};

    sifter_tracer(std::string file): m_init(0) {
        std::ifstream ifs(file);

        if (!ifs) {
            std::cerr << "Failed to create tracer. " << file
                << " does not exist\n";
            return;
        }

        ifs >> m_name;
        char cfg_type;
        while (ifs >> cfg_type) {
            switch (cfg_type) {
                case 'p': {
                    bool is_entry;
                    std::string event, entry;
                    ifs >> is_entry >> event >> entry;
                    add_prog(is_entry, event, entry);
                    break;
                }
                case 'm': {
                    int type;
                    std::string name;
                    ifs >> type >> name;
                    add_map(type, name);
                    break;
                }
                default:
                    std::cerr << "Failed to create tracer: invalid cfg_type "
                        << cfg_type << "\n";
                    return;
            }
        }

        m_init = 1;
    };
};

int main(int argc, char *argv[]) {
    bool manual_mode = false;
    int log_interval = 10;
    char *config_file = nullptr;
    char *log_file = nullptr;

    int opt;
    while ((opt = getopt (argc, argv, "mi:c:o:")) != -1) {
        switch (opt) {
            case 'm': manual_mode = true; break;
            case 'i': log_interval = atoi(optarg); break;
            case 'c': config_file = optarg; break;
            case 'o': log_file = optarg; break;
            case '?':
                if (optopt == 'c')
                    fprintf (stderr, "Option -%c requires an argument.\n", optopt);
                else if (isprint (optopt))
                    fprintf (stderr, "Unknown option `-%c'.\n", optopt);
                else
                    fprintf (stderr, "Unknown option character `\\x%x'.\n", optopt);
                return 1;
            default: abort();
        }
    }

    sifter_tracer tracer(config_file);

    if (!tracer)
        return 1;

    tracer.attach_prog();

    if (manual_mode) {
        std::cout << "\nPress enter to read map values...\n";
        std::cin.get();
        tracer.print_maps();
        return 0;
    }

    tracer.recover_maps(log_file);
    std::string tmp_file = std::string(log_file) + ".tmp";
    while (1) {
        tracer.update_maps();
        tracer.dump_maps(tmp_file);
        std::rename(tmp_file.c_str(), log_file);
        sleep(log_interval);
    }

}
