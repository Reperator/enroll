#include "enroll.h"

char *email = NULL, *first = NULL, *last = NULL;
uint16_t team = 0, project;

uint64_t challenge, nonce = 0;

uint16_t num_threads = 0;

char constant_payload[1000];
size_t payload_size;

float *hash_rates;

long get_cpus(void) {
#if defined(__linux__) || defined(__APPLE__) || defined(__FreeBSD__)
    long num_cpus = sysconf(_SC_NPROCESSORS_ONLN);
    if (num_cpus > 0)
        return num_cpus;
#endif
    warn("cannot get number of CPUs; defaulting to 1");
    return 1;
}

void *brute_force(void *arg) {
    uint64_t const thread_id = *((uint64_t *) arg);
    free(arg);

    uint8_t packet[payload_size - sizeof(enroll_header)];
    enroll_register *header = (enroll_register *) packet;
    header->challenge = challenge;
    header->team = team;
    header->project = project;
    header->nonce = thread_id;
    memcpy(packet + sizeof(enroll_register),
        constant_payload,
        strlen(constant_payload));

    uint8_t md[EVP_MAX_MD_SIZE];
    u8_a md_a = md;
    uint32_t md_len;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    const EVP_MD *sha256 = EVP_sha256();

    uint64_t hash_count = 0;
    struct timespec time;
    if (clock_gettime(CLOCK_REALTIME, &time))
        warn("could not get time");
    uint64_t start_time = TIME(time), time_diff;

    do {
        header->nonce += num_threads;
        EVP_DigestInit_ex(ctx, sha256, NULL);
        EVP_DigestUpdate(ctx, packet, payload_size - sizeof(enroll_header));
        EVP_DigestFinal_ex(ctx, md, &md_len);
        if ((hash_count++ & 0x7fffff) == 0) {
            if (clock_gettime(CLOCK_REALTIME, &time))
                warn("could not get time");
            time_diff = TIME(time) - start_time;
            hash_rates[thread_id] = ((float) hash_count) / ((float) time_diff);
            if (thread_id == 0) {
                float total_rate = 0.0;
                for (int i = 0; i < num_threads; i++)
                    total_rate += hash_rates[i];
                info("%.03f MH/s", total_rate);
            }
        }
    } while (*((uint32_t *) md_a) != 0 && !nonce);

    if (*((uint32_t *) md_a) == 0) {
        info("thread %" PRIu64 " found valid nonce %#018" PRIx64, thread_id, header->nonce);
        nonce = header->nonce;
        print_hash(md, md_len);
    }

    pthread_exit(NULL);
}

int main(int argc, char **argv) {
    int flag;
    bool dry_run = false, have_challenge = false;
    char *outfile = NULL;

    opterr = 0; // suppress getopt errors
    while ((flag = getopt(argc, argv, "T:e:f:l:dp:t:o:c:")) != -1) {
        switch (flag) {
            case 'T':
                num_threads = (uint16_t) strtoul(optarg, NULL, 10);
                break;
            case 'e':
                email = optarg;
                break;
            case 'f':
                first = optarg;
                break;
            case 'l':
                last = optarg;
                break;
            case 'd':
                dry_run = true;
                break;
            case 'p':
                if (!strcmp("DHT", optarg))
                    project = htons(DHT);
                else if (!strcmp("RPS", optarg))
                    project = htons(RPS);
                else if (!strcmp("NSE", optarg))
                    project = htons(NSE);
                else if (!strcmp("Onion", optarg))
                    project = htons(Onion);
                else
                    error("unknown project %s" USAGE, optarg);
                break;
            case 't':
                team = htons((uint16_t) strtoul(optarg, NULL, 10));
                break;
            case 'o':
                outfile = optarg;
                break;
            case 'c':
                if (sscanf(optarg, "0x%018" PRIx64, &challenge) != 1) {
                    warn("could not parse challenge; using fixed challenge 0x0123456789abcdef");
                    challenge = 0x0123456789abcdef;
                }
                have_challenge = true;
                break;
            case '?':
            default:
                error("illegal option '-%c'\n" USAGE, optopt);
        }
    }

    if (!email || !first || !last || !project)
        error(USAGE);

    sprintf(constant_payload, "%s\r\n%s\r\n%s", email, first, last);
    payload_size = sizeof(enroll_header) + sizeof(enroll_register) + strlen(constant_payload);

    if (!num_threads) {
        info("-T not specified; using one thread per CPU");
        num_threads = get_cpus();
    }

    info("using %hu threads", num_threads);

    if (dry_run)
        info("doing dry run; no network traffic will be sent");

    int sock = -1;
    if (!have_challenge) {
        if (!dry_run) {
            info("getting address for " HOST);
            struct hostent *host = gethostbyname(HOST);

            if (!host)
                error("could not resolve " HOST);

            sock = socket(PF_INET, SOCK_STREAM, 0);

            if (sock == -1)
                error("could not create socket");

            struct sockaddr_in addr;
            addr.sin_family = AF_INET;
            addr.sin_port = htons(PORT);
            memcpy(&addr.sin_addr.s_addr, host->h_addr_list[0], host->h_length);

            if (connect(sock, (struct sockaddr *) &addr, sizeof(struct sockaddr_in)) < 0)
                error("could not connect to host");

            uint8_t init_packet[sizeof(enroll_header) + sizeof(enroll_init)];
            enroll_header *hdr = (enroll_header *) init_packet;
            enroll_init *init = (enroll_init *) (init_packet + sizeof(enroll_header));
            if (read(sock, init_packet, 12) != 12)
                error("server did not send ENROLL INIT");

            if (ntohs(hdr->size) != 12) {
                warn("ENROLL INIT size field is %d, expected 12", ntohs(hdr->size));
            }

            if (ntohs(hdr->type) != ENROLL_INIT)
                error("ENROLL INIT type is %d, expected ENROLL_INIT (%d)", ntohs(hdr->type), ENROLL_INIT);

            challenge = init->challenge;
        } else {
            challenge = 0x0123456789abcdef;
        }
    }

    info("using %s", OpenSSL_version(OPENSSL_VERSION));

    if (!(hash_rates = malloc(sizeof(float) * num_threads)))
        error("malloc failed");

    for (int i = 0; i < num_threads; i++)
        hash_rates[i] = 0.0;

    info("received challenge %#018" PRIx64 "; beginning brute-force", challenge);
    pthread_t threads[num_threads];
    for (uint64_t i = 0; i < num_threads; i++) {
        uint64_t *thread_id = (uint64_t *) malloc(sizeof(uint64_t));
        if (!thread_id)
            error("malloc failed");
        *thread_id = i;
        if (pthread_create(&threads[i], NULL, &brute_force, (void *) thread_id))
            error("could not create thread %" PRIu64, i);
    }

    for (uint64_t i = 0; i < num_threads; i++) {
        if (pthread_join(threads[i], NULL))
            error("could not join worker thread %" PRIu64, i);
    }
    free(hash_rates);

    info("nonce %#018" PRIx64 " found by thread %" PRIu64, nonce, nonce % num_threads);

    uint8_t packet[payload_size];
    enroll_header *hdr = (enroll_header *) packet;
    enroll_register *reg = (enroll_register *) (packet + sizeof(enroll_header));
    hdr->size = htons(payload_size);
    hdr->type = htons(ENROLL_REGISTER);
    reg->challenge = challenge;
    reg->team = team;
    reg->project = project;
    reg->nonce = nonce;
    memcpy(packet + sizeof(enroll_header) + sizeof(enroll_register),
        constant_payload,
        strlen(constant_payload));

    if (outfile) {
        FILE *fd = fopen(outfile, "w");
        if (!fd) {
            warn("could not open %s", outfile);
        } else {
            if (fwrite(packet, sizeof(uint8_t), payload_size, fd) != payload_size)
                warn("could not write %ld bytes to %s", payload_size, outfile);
            else
                info("wrote %ld bytes to %s", payload_size, outfile);

            if (fclose(fd))
                warn("could not close %s", outfile);
        }
    }

    uint8_t md[EVP_MAX_MD_SIZE];
    u8_a md_a = md;
    uint32_t md_len;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, packet + sizeof(enroll_header), payload_size - sizeof(enroll_header));
    EVP_DigestFinal_ex(ctx, md, &md_len);

    print_hash(md, md_len);
    if (*((uint32_t *) md_a) == 0)
        info("sanity check successful");
    else
        error("sanity check failed!");

    if (!dry_run) {
        if (write(sock, packet, payload_size) != payload_size)
            error("could not write packet");

        uint8_t response[1000];
        enroll_header *hdr = (enroll_header *) response;
        ssize_t read_bytes = read(sock, response, 1000);
        if (read_bytes >= sizeof(enroll_header)) {
            if (read_bytes != ntohs(hdr->size))
                warn("read %ld bytes but message size is %d bytes", read_bytes, ntohs(hdr->size));

            switch (ntohs(hdr->type)) {
                case ENROLL_FAILURE:;
                    enroll_failure *fail = (enroll_failure *) (response + sizeof(enroll_header));
                    response[read_bytes] = 0; // manually append a null byte to be safe
                    warn("ENROLL FAILURE: reserved %d, error number %d, message \"%s\"",
                        ntohs(fail->reserved),
                        ntohs(fail->error),
                        (char *) response + sizeof(enroll_header) + sizeof(enroll_failure));
                    break;
                case ENROLL_SUCCESS:;
                    enroll_success *succ = (enroll_success *) (response + sizeof(enroll_header));
                    info("ENROLL SUCCESS: reserved %d, team %d", ntohs(succ->reserved), ntohs(succ->team));
                    break;
                default:
                    warn("unknown ENROLL type %d", ntohs(hdr->type));
            }
        } else {
            warn("<4 bytes received; cannot analyze response");
        }
        if (close(sock))
            warn("could not close server connection");
    }

    return EXIT_SUCCESS;
}
