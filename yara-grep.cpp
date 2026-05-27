#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <iomanip>
#include <cstdlib>
#include <yara.h>

static constexpr int DEFAULT_CONTEXT_RADIUS = 16;

struct ScanCtx {
    const uint8_t* data;
    size_t         size;
    int            radius;
};

static void print_row(uint64_t offset, const uint8_t* row, size_t len) {
    std::cout << "  " << std::hex << std::setw(8) << std::setfill('0') << offset << ":  ";
    for (size_t i = 0; i < 16; ++i) {
        if (i < len)
            std::cout << std::hex << std::setw(2) << std::setfill('0')
                      << static_cast<unsigned>(row[i]) << ' ';
        else
            std::cout << "   ";
        if (i == 7) std::cout << ' ';
    }
    std::cout << " |";
    for (size_t i = 0; i < len; ++i)
        std::cout << (std::isprint(row[i]) ? static_cast<char>(row[i]) : '.');
    std::cout << "|\n";
}

static void print_context(const ScanCtx& ctx, uint64_t match_offset, size_t match_len) {
    int64_t start = static_cast<int64_t>(match_offset) - ctx.radius;
    if (start < 0) start = 0;
    start -= start % 16;

    int64_t end = static_cast<int64_t>(match_offset) + static_cast<int64_t>(match_len) + ctx.radius;
    if (end > static_cast<int64_t>(ctx.size)) end = static_cast<int64_t>(ctx.size);

    for (int64_t off = start; off < end; off += 16) {
        size_t row_len = static_cast<size_t>(std::min(static_cast<int64_t>(16), end - off));
        print_row(static_cast<uint64_t>(off), ctx.data + off, row_len);
    }
}

static int on_match(YR_SCAN_CONTEXT* scan_ctx, int message, void* message_data, void* user_data) {
    if (message != CALLBACK_MSG_RULE_MATCHING) return CALLBACK_CONTINUE;

    auto* rule = static_cast<YR_RULE*>(message_data);
    auto* ctx  = static_cast<ScanCtx*>(user_data);

    YR_STRING* string;
    yr_rule_strings_foreach(rule, string) {
        YR_MATCH* match;
        yr_string_matches_foreach(scan_ctx, string, match) {
            std::cout << "[0x" << std::hex << std::setw(8) << std::setfill('0')
                      << match->base + match->offset << "] "
                      << rule->identifier << " hit " << string->identifier
                      << " (" << std::dec << match->match_length << " bytes)\n";
            print_context(*ctx, match->base + match->offset,
                          static_cast<size_t>(match->match_length));
            std::cout << '\n';
        }
    }
    return CALLBACK_CONTINUE;
}

static void usage(const char* prog) {
    std::cerr << "usage: " << prog << " <rule.yar> <target> [-C <bytes>]\n";
}

static std::vector<uint8_t> read_file(const char* path) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) return {};
    auto sz = f.tellg();
    f.seekg(0);
    std::vector<uint8_t> buf(static_cast<size_t>(sz));
    f.read(reinterpret_cast<char*>(buf.data()), sz);
    return buf;
}

int main(int argc, char* argv[]) {
    if (argc < 3) { usage(argv[0]); return EXIT_FAILURE; }

    const char* rule_path   = argv[1];
    const char* target_path = argv[2];
    int         radius      = DEFAULT_CONTEXT_RADIUS;

    for (int i = 3; i < argc - 1; ++i) {
        if (std::string(argv[i]) == "-C") {
            char* end = nullptr;
            long  val = std::strtol(argv[++i], &end, 10);
            if (end == argv[i] || val <= 0) {
                std::cerr << "-C needs a positive number\n";
                return EXIT_FAILURE;
            }
            radius = static_cast<int>(val);
        }
    }

    auto file_data = read_file(target_path);
    if (file_data.empty()) {
        std::cerr << "can't read " << target_path << '\n';
        return EXIT_FAILURE;
    }

    if (yr_initialize() != ERROR_SUCCESS) {
        std::cerr << "yara init failed\n";
        return EXIT_FAILURE;
    }

    int          exit_code = EXIT_SUCCESS;
    YR_COMPILER* compiler  = nullptr;
    YR_RULES*    rules     = nullptr;

    if (yr_compiler_create(&compiler) != ERROR_SUCCESS) {
        std::cerr << "couldn't create compiler\n";
        exit_code = EXIT_FAILURE;
        goto cleanup;
    }

    {
        FILE* fh = std::fopen(rule_path, "r");
        if (!fh) {
            std::cerr << "can't open " << rule_path << '\n';
            exit_code = EXIT_FAILURE;
            goto cleanup;
        }
        int rc = yr_compiler_add_file(compiler, fh, nullptr, rule_path);
        std::fclose(fh);
        if (rc != 0) {
            std::cerr << "rule file has errors\n";
            exit_code = EXIT_FAILURE;
            goto cleanup;
        }
    }

    if (yr_compiler_get_rules(compiler, &rules) != ERROR_SUCCESS) {
        std::cerr << "couldn't get rules\n";
        exit_code = EXIT_FAILURE;
        goto cleanup;
    }

    {
        ScanCtx ctx{ file_data.data(), file_data.size(), radius };
        if (yr_rules_scan_mem(rules, file_data.data(), file_data.size(),
                              0, on_match, &ctx, 0) != ERROR_SUCCESS)
            std::cerr << "scan ended early\n";
    }

cleanup:
    if (rules)    yr_rules_destroy(rules);
    if (compiler) yr_compiler_destroy(compiler);
    yr_finalize();
    return exit_code;
}
