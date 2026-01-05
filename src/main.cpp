#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <openssl/evp.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <csignal>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <optional>
#include <random>
#include <sstream>
#include <string>
#include <vector>

namespace fs = std::filesystem;

namespace {

volatile std::sig_atomic_t g_should_stop = 0;
std::ofstream g_log_stream;

std::string log_timestamp() {
    auto now = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::tm tm {};
    localtime_r(&t, &tm);
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
    return oss.str();
}

void handle_signal(int) { g_should_stop = 1; }

std::string now_string() {
    auto now = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::tm tm {};
    localtime_r(&t, &tm);
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y%m%d_%H%M%S");
    return oss.str();
}

std::string to_hex(const unsigned char* data, std::size_t len) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (std::size_t i = 0; i < len; ++i) {
        oss << std::setw(2) << static_cast<int>(data[i]);
    }
    return oss.str();
}

std::string sha256_hex(const std::string& input) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(input.data()), input.size(), hash);
    return to_hex(hash, SHA256_DIGEST_LENGTH);
}

std::string md5_hex(const fs::path& file) {
    unsigned char buffer[4096];
    unsigned char md[MD5_DIGEST_LENGTH];
    MD5_CTX ctx;
    MD5_Init(&ctx);
    std::ifstream in(file, std::ios::binary);
    if (!in) {
        return {};
    }
    while (in) {
        in.read(reinterpret_cast<char*>(buffer), sizeof(buffer));
        std::streamsize n = in.gcount();
        if (n > 0) {
            MD5_Update(&ctx, buffer, static_cast<std::size_t>(n));
        }
    }
    MD5_Final(md, &ctx);
    return to_hex(md, MD5_DIGEST_LENGTH);
}

std::string pbkdf2_sha256_hex(const std::string& password, const std::string& salt, int iterations = 10000) {
    unsigned char derived[SHA256_DIGEST_LENGTH];
    if (PKCS5_PBKDF2_HMAC(password.c_str(), static_cast<int>(password.size()),
                          reinterpret_cast<const unsigned char*>(salt.c_str()), static_cast<int>(salt.size()),
                          iterations, EVP_sha256(), sizeof(derived), derived) != 1) {
        return {};
    }
    return to_hex(derived, sizeof(derived));
}

void log(const std::string& level, const std::string& msg) {
    std::string line = log_timestamp() + " [" + level + "] " + msg;
    std::cerr << line << std::endl;
    if (g_log_stream.is_open()) {
        g_log_stream << line << std::endl;
    }
}

void configure_logging(const fs::path& logfile) {
    if (logfile.empty()) return;
    if (g_log_stream.is_open()) {
        g_log_stream.close();
    }
    std::error_code ec;
    if (!logfile.parent_path().empty()) {
        fs::create_directories(logfile.parent_path(), ec);
    }
    g_log_stream.open(logfile, std::ios::app);
    if (!g_log_stream.is_open()) {
        std::cerr << "[WARN] Failed to open log file " << logfile << ": " << std::strerror(errno) << std::endl;
    } else {
        g_log_stream << log_timestamp() << " [INFO] Logging initialized" << std::endl;
    }
}

struct Config {
    uint16_t ota_port = 3232;
    std::string ota_password;
    std::string bind_address = "0.0.0.0";
    fs::path running_path = "./host_firmware";
    std::string running_filename;
    fs::path backup_path = "./backups";
    fs::path temp_path = "./tmp";
    std::size_t backup_keep = 10;
    bool run_in_background = false;
    bool exit_after_exec = false;
    int watchdog_interval_seconds = 30;
    fs::path log_path = "/var/log/esphome_hostota.log";
    fs::path target_path() const {
        return running_filename.empty() ? running_path : running_path / running_filename;
    }
    fs::path pid_file() const { return target_path().string() + ".pid"; }
};

std::optional<std::string> read_file(const fs::path& path) {
    std::ifstream in(path);
    if (!in) return std::nullopt;
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

std::optional<fs::path> find_config(const std::optional<fs::path>& override_path) {
    if (override_path && fs::exists(*override_path)) {
        return override_path;
    }

    std::error_code ec;
    fs::path exe = fs::read_symlink("/proc/self/exe", ec);
    if (ec) {
        exe = fs::current_path();
    }
    fs::path exe_dir = exe.parent_path();
    std::vector<fs::path> candidates = {
        exe_dir / "esphome_hostota.conf",
        exe_dir / "config" / "esphome_hostota.conf",
        "/etc/esphome_hostota.conf",
        "/etc/esphome_hostota/esphome_hostota.conf"
    };
    if (const char* home = std::getenv("HOME")) {
        candidates.emplace_back(fs::path(home) / ".config" / "esphome_hostota.conf");
    }
    for (const auto& p : candidates) {
        if (fs::exists(p)) return p;
    }
    return std::nullopt;
}

void ensure_directories(const Config& cfg) {
    fs::create_directories(cfg.backup_path);
    fs::create_directories(cfg.temp_path);
    if (!cfg.target_path().parent_path().empty()) {
        fs::create_directories(cfg.target_path().parent_path());
    }
}

std::optional<pid_t> read_pid_file(const fs::path& pid_path) {
    if (!fs::exists(pid_path)) return std::nullopt;
    std::ifstream in(pid_path);
    pid_t pid;
    if (in >> pid) {
        return pid;
    }
    return std::nullopt;
}

std::optional<pid_t> find_pid_by_exe(const fs::path& target) {
    if (target.empty()) return std::nullopt;
    std::error_code ec;
    fs::path canonical_target = fs::weakly_canonical(target, ec);
    if (ec) canonical_target = target;
    for (const auto& entry : fs::directory_iterator("/proc")) {
        if (!entry.is_directory()) continue;
        const std::string name = entry.path().filename().string();
        if (!std::all_of(name.begin(), name.end(), ::isdigit)) continue;
        pid_t pid = static_cast<pid_t>(std::stoi(name));
        if (pid == getpid()) continue;
        fs::path exe = fs::read_symlink(entry.path() / "exe", ec);
        if (ec) continue;
        if (fs::equivalent(exe, canonical_target, ec) || (!ec && exe == canonical_target)) {
            return pid;
        }
    }
    return std::nullopt;
}

bool parse_bool(const std::string& value) {
    std::string lower = value;
    for (auto& c : lower) c = static_cast<char>(std::tolower(c));
    return lower == "1" || lower == "true" || lower == "yes" || lower == "on";
}

Config load_config(const std::optional<fs::path>& override_path, bool& used_defaults) {
    Config cfg;
    used_defaults = false;
    auto maybe = find_config(override_path);
    if (!maybe) {
        used_defaults = true;
        log("WARN", "No configuration file found. Using defaults.");
        return cfg;
    }
    auto content_opt = read_file(*maybe);
    if (!content_opt) {
        used_defaults = true;
        log("WARN", "Unable to read config file, using defaults.");
        return cfg;
    }
    std::istringstream iss(*content_opt);
    std::string line;
    while (std::getline(iss, line)) {
        if (line.empty() || line[0] == '#') continue;
        auto eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string key = line.substr(0, eq);
        std::string val = line.substr(eq + 1);
        if (key == "ota_port") cfg.ota_port = static_cast<uint16_t>(std::stoi(val));
        else if (key == "ota_password") cfg.ota_password = val;
        else if (key == "bind_address") cfg.bind_address = val;
        else if (key == "running_path") cfg.running_path = val;
        else if (key == "backup_path") cfg.backup_path = val;
        else if (key == "temp_path") cfg.temp_path = val;
        else if (key == "backup_keep") cfg.backup_keep = static_cast<std::size_t>(std::stoul(val));
        else if (key == "run_in_background") cfg.run_in_background = parse_bool(val);
        else if (key == "exit_after_exec") cfg.exit_after_exec = parse_bool(val);
        else if (key == "running_filename") cfg.running_filename = val;
        else if (key == "watchdog_interval_seconds") cfg.watchdog_interval_seconds = std::stoi(val);
        else if (key == "log_path") cfg.log_path = val;
    }
    log("INFO", "Loaded config from " + maybe->string());
    return cfg;
}

std::string random_nonce() {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint32_t> dist(0, 0xffffffff);
    std::ostringstream oss;
    for (int i = 0; i < 8; ++i) {
        oss << std::hex << std::setw(8) << std::setfill('0') << dist(gen);
    }
    return oss.str();
}

void trim_backups(const Config& cfg) {
    if (cfg.backup_keep == 0 || !fs::exists(cfg.backup_path)) return;
    std::vector<fs::directory_entry> entries;
    for (const auto& entry : fs::directory_iterator(cfg.backup_path)) {
        if (entry.is_regular_file()) entries.push_back(entry);
    }
    if (entries.size() <= cfg.backup_keep) return;
    std::sort(entries.begin(), entries.end(),
              [](const auto& a, const auto& b) { return fs::last_write_time(a) < fs::last_write_time(b); });
    for (std::size_t i = 0; i + cfg.backup_keep < entries.size(); ++i) {
        std::error_code ec;
        fs::remove(entries[i], ec);
        if (!ec) log("INFO", "Removed old backup: " + entries[i].path().string());
    }
}

bool kill_existing_process(const Config& cfg) {
    fs::path pid_path = cfg.pid_file();
    auto pid_opt = read_pid_file(pid_path);
    if (!pid_opt) return true;
    pid_t pid = *pid_opt;
    if (pid <= 0) return true;
    log("INFO", "Attempting to terminate existing process PID " + std::to_string(pid));
    if (kill(pid, SIGTERM) != 0 && errno != ESRCH) {
        log("WARN", "Failed to send SIGTERM to PID " + std::to_string(pid) + ": " + std::strerror(errno));
    }
    for (int i = 0; i < 50; ++i) {
        if (kill(pid, 0) != 0) {
            return true;
        }
        usleep(100000);
    }
    if (kill(pid, SIGKILL) != 0 && errno != ESRCH) {
        log("ERROR", "Failed to SIGKILL PID " + std::to_string(pid) + ": " + std::strerror(errno));
        return false;
    }
    return true;
}

bool move_to_backup(const Config& cfg) {
    fs::path current = cfg.target_path();
    if (!fs::exists(current)) return true;
    ensure_directories(cfg);
    fs::path backup_target = cfg.backup_path / ("bak_" + now_string());
    std::error_code ec;
    fs::rename(current, backup_target, ec);
    if (ec) {
        log("ERROR", "Failed to move existing binary to backup: " + ec.message());
        return false;
    }
    log("INFO", "Moved existing binary to " + backup_target.string());
    trim_backups(cfg);
    return true;
}

bool promote_new_binary(const Config& cfg, const fs::path& temp_file) {
    std::error_code ec;
    fs::permissions(temp_file, fs::perms::owner_exec | fs::perms::group_exec | fs::perms::others_exec |
                                   fs::perms::owner_read | fs::perms::owner_write | fs::perms::group_read |
                                   fs::perms::others_read,
                    fs::perm_options::add, ec);
    if (ec) {
        log("WARN", "Failed to set executable permissions: " + ec.message());
    }
    fs::rename(temp_file, cfg.target_path(), ec);
    if (ec) {
        log("ERROR", "Failed to move new binary to running location: " + ec.message());
        return false;
    }
    log("INFO", "New binary moved to " + cfg.target_path().string());
    return true;
}

bool launch_binary(const Config& cfg) {
    pid_t pid = fork();
    if (pid < 0) {
        log("ERROR", "Failed to fork: " + std::string(std::strerror(errno)));
        return false;
    }
    if (pid == 0) {
        if (cfg.run_in_background) {
            if (setsid() < 0) {
                _exit(1);
            }
            int fd = open("/dev/null", O_RDWR);
            if (fd >= 0) {
                dup2(fd, STDIN_FILENO);
                dup2(fd, STDOUT_FILENO);
                dup2(fd, STDERR_FILENO);
                if (fd > 2) close(fd);
            }
        }
        fs::path binary_path = cfg.target_path();
        execl(binary_path.c_str(), binary_path.c_str(), static_cast<char*>(nullptr));
        _exit(1);
    }
    std::ofstream out(cfg.pid_file());
    out << pid;
    log("INFO", "Launched new binary with PID " + std::to_string(pid));
    return true;
}

struct Invitation {
    int command = 0;
    uint16_t host_port = 0;
    std::size_t size = 0;
    std::string md5;
};

bool parse_invitation(const std::string& payload, Invitation& out) {
    std::istringstream ss(payload);
    ss >> out.command >> out.host_port >> out.size >> out.md5;
    return ss && (out.command == 0 || out.command == 100) && out.md5.size() == 32;
}

class OtaServer {
public:
    explicit OtaServer(Config cfg) : cfg_(std::move(cfg)) {
        password_hash_ = cfg_.ota_password.empty() ? "" : sha256_hex(cfg_.ota_password);
        last_watchdog_check_ = std::chrono::steady_clock::now();
    }

    bool start() {
        udp_fd_ = socket(AF_INET, SOCK_DGRAM, 0);
        if (udp_fd_ < 0) {
            log("ERROR", "Unable to create UDP socket: " + std::string(std::strerror(errno)));
            return false;
        }
        sockaddr_in addr {};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(cfg_.ota_port);
        addr.sin_addr.s_addr = inet_addr(cfg_.bind_address.c_str());
        if (bind(udp_fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
            log("ERROR", "Bind failed: " + std::string(std::strerror(errno)));
            return false;
        }
        log("INFO", "Listening for OTA invitations on " + cfg_.bind_address + ":" + std::to_string(cfg_.ota_port));
        return true;
    }

    void loop() {
        while (!g_should_stop) {
            fd_set rfds;
            FD_ZERO(&rfds);
            FD_SET(udp_fd_, &rfds);
            timeval tv {1, 0};
            int ret = select(udp_fd_ + 1, &rfds, nullptr, nullptr, &tv);
            if (ret < 0) {
                if (errno == EINTR) continue;
                log("ERROR", "select failed: " + std::string(std::strerror(errno)));
                break;
            }
            if (FD_ISSET(udp_fd_, &rfds)) {
                handle_udp();
            }
            run_watchdog();
        }
    }

private:
    enum class State { Idle, WaitAuth } state_ = State::Idle;
    Config cfg_;
    std::string password_hash_;
    std::string nonce_;
    Invitation invitation_;
    sockaddr_in last_remote_ {};
    int udp_fd_ = -1;
    bool update_in_progress_ = false;
    std::chrono::steady_clock::time_point last_watchdog_check_ {};

    void handle_udp() {
        char buffer[256];
        sockaddr_in remote {};
        socklen_t len = sizeof(remote);
        ssize_t received = recvfrom(udp_fd_, buffer, sizeof(buffer) - 1, 0, reinterpret_cast<sockaddr*>(&remote), &len);
        if (received <= 0) return;
        buffer[received] = '\0';
        std::string payload(buffer);
        if (state_ == State::Idle) {
            if (!parse_invitation(payload, invitation_)) {
                log("WARN", "Received invalid invitation: " + payload);
                return;
            }
            last_remote_ = remote;
            if (!password_hash_.empty()) {
                nonce_ = random_nonce();
                send_response("AUTH " + nonce_, remote);
                state_ = State::WaitAuth;
                log("INFO", "Auth requested from " + std::string(inet_ntoa(remote.sin_addr)));
            } else {
                send_response("OK", remote);
                process_update(remote);
            }
        } else {
            int cmd = 0;
            std::istringstream ss(payload);
            std::string cnonce, response;
            ss >> cmd >> cnonce >> response;
            if (cmd != 200 || cnonce.size() != 64 || response.size() != 64) {
                log("WARN", "Invalid auth response");
                state_ = State::Idle;
                return;
            }
            if (remote.sin_addr.s_addr != last_remote_.sin_addr.s_addr) {
                log("WARN", "Auth response from unexpected host");
                state_ = State::Idle;
                return;
            }
            std::string salt = nonce_ + ":" + cnonce;
            std::string derived = pbkdf2_sha256_hex(password_hash_, salt);
            std::string challenge = derived + ":" + nonce_ + ":" + cnonce;
            std::string expected = sha256_hex(challenge);
            if (expected == response) {
                send_response("OK", remote);
                log("INFO", "Authentication successful");
                process_update(remote);
            } else {
                send_response("Authentication Failed", remote);
                log("WARN", "Authentication failed");
            }
            state_ = State::Idle;
        }
    }

    void send_response(const std::string& msg, const sockaddr_in& remote) {
        sendto(udp_fd_, msg.c_str(), msg.size(), 0, reinterpret_cast<const sockaddr*>(&remote), sizeof(remote));
    }

    void process_update(const sockaddr_in& remote) {
        struct FlagGuard {
            bool& flag;
            explicit FlagGuard(bool& f) : flag(f) { flag = true; }
            ~FlagGuard() { flag = false; }
        } guard(update_in_progress_);
        std::string host_ip = inet_ntoa(remote.sin_addr);
        log("INFO", "Starting update from " + host_ip + ":" + std::to_string(invitation_.host_port));
        ensure_directories(cfg_);
        std::string temp_name = "ota_" + now_string();
        fs::path temp_file = cfg_.temp_path / temp_name;
        int tcp_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (tcp_fd < 0) {
            log("ERROR", "Failed to create TCP socket: " + std::string(std::strerror(errno)));
            return;
        }
        sockaddr_in server {};
        server.sin_family = AF_INET;
        server.sin_port = htons(invitation_.host_port);
        inet_pton(AF_INET, host_ip.c_str(), &server.sin_addr);
        if (connect(tcp_fd, reinterpret_cast<sockaddr*>(&server), sizeof(server)) < 0) {
            log("ERROR", "TCP connect failed: " + std::string(std::strerror(errno)));
            close(tcp_fd);
            return;
        }
        std::ofstream out(temp_file, std::ios::binary);
        if (!out) {
            log("ERROR", "Unable to open temp file for writing");
            close(tcp_fd);
            return;
        }
        std::vector<char> buf(1460);
        std::size_t total = 0;
        bool failed = false;
        while (total < invitation_.size) {
            std::size_t to_read = std::min<std::size_t>(buf.size(), invitation_.size - total);
            ssize_t n = recv(tcp_fd, buf.data(), to_read, 0);
            if (n <= 0) {
                log("ERROR", "Receive failed during update");
                failed = true;
                break;
            }
            out.write(buf.data(), n);
            total += static_cast<std::size_t>(n);
            std::string ack = std::to_string(n);
            send(tcp_fd, ack.c_str(), ack.size(), 0);
        }
        if (!failed) {
            out.flush();
            out.close();
            std::string actual_md5 = md5_hex(temp_file);
            if (actual_md5 != invitation_.md5) {
                log("ERROR", "MD5 mismatch. Expected " + invitation_.md5 + " got " + actual_md5);
                failed = true;
            }
        }
        if (!failed) {
            send(tcp_fd, "OK", 2, 0);
        }
        close(tcp_fd);
        if (failed) {
            std::error_code ec;
            fs::remove(temp_file, ec);
            return;
        }

        if (!kill_existing_process(cfg_)) {
            log("ERROR", "Could not stop existing process");
            return;
        }
        if (!move_to_backup(cfg_)) {
            log("ERROR", "Could not rotate existing binary");
            return;
        }
        if (!promote_new_binary(cfg_, temp_file)) {
            return;
        }
        if (!launch_binary(cfg_)) {
            log("ERROR", "Failed to launch new binary");
            return;
        }
        if (cfg_.exit_after_exec) {
            log("INFO", "exit_after_exec enabled, shutting down OTA server.");
            std::raise(SIGTERM);
        }
    }

    bool binary_running() {
        fs::path pid_path = cfg_.pid_file();
        auto pid_opt = read_pid_file(pid_path);
        if (pid_opt && *pid_opt > 0) {
            if (kill(*pid_opt, 0) == 0) return true;
            if (errno != ESRCH) {
                log("WARN", "Unable to query process state for PID " + std::to_string(*pid_opt) + ": " +
                                 std::strerror(errno));
            }
        }

        auto by_exe = find_pid_by_exe(cfg_.target_path());
        if (by_exe && *by_exe > 0) {
            std::ofstream out(pid_path);
            if (out) {
                out << *by_exe;
                log("INFO", "Watchdog found running process for target, refreshed PID file with " +
                                  std::to_string(*by_exe));
            }
            return true;
        }
        return false;
    }

    void run_watchdog() {
        if (cfg_.watchdog_interval_seconds <= 0) return;
        auto now = std::chrono::steady_clock::now();
        if (std::chrono::duration_cast<std::chrono::seconds>(now - last_watchdog_check_).count() <
            cfg_.watchdog_interval_seconds) {
            return;
        }
        last_watchdog_check_ = now;
        if (update_in_progress_) {
            log("INFO", "Watchdog skipped while update in progress");
            return;
        }
        if (binary_running()) {
            return;
        }
        if (!fs::exists(cfg_.target_path())) {
            log("WARN", "Watchdog could not find binary at " + cfg_.target_path().string());
            return;
        }
        log("WARN", "Watchdog restarting missing binary");
        if (!kill_existing_process(cfg_)) {
            log("ERROR", "Watchdog failed to clean up previous process");
            return;
        }
        if (!launch_binary(cfg_)) {
            log("ERROR", "Watchdog failed to launch binary");
        }
    }
};

void print_help() {
    std::cout << "ESPHome Host OTA Server\n"
              << "Usage: esphome_hostota [-c path_to_config] [--foreground]\n"
              << "Configuration search order: executable directory, /etc/esphome_hostota.conf,\n"
              << "/etc/esphome_hostota/esphome_hostota.conf, ~/.config/esphome_hostota.conf\n";
}

}  // namespace

int main(int argc, char* argv[]) {
    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);

    std::optional<fs::path> config_override;
    bool force_foreground = false;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-c" && i + 1 < argc) {
            config_override = fs::path(argv[++i]);
        } else if (arg == "--foreground") {
            force_foreground = true;
        } else if (arg == "-h" || arg == "--help") {
            print_help();
            return 0;
        }
    }

    bool used_defaults = false;
    Config cfg = load_config(config_override, used_defaults);
    if (used_defaults) {
        log("WARN", "Create a config file similar to config.example.conf to override defaults.");
    }

    configure_logging(cfg.log_path);

    if (cfg.run_in_background && !force_foreground) {
        if (daemon(0, 0) != 0) {
            log("ERROR", "Failed to daemonize: " + std::string(std::strerror(errno)));
            return 1;
        }
    }

    OtaServer server(cfg);
    if (!server.start()) {
        return 1;
    }
    server.loop();
    return 0;
}
