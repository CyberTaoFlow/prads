#ifndef NDPI_ENGINE_H
#define NDPI_ENGINE_H
#ifdef HAVE_NDPI

/* Bits for connection->ndpi_flags */
#define NDPI_FL_DONE        0x0001  /* nDPI fully classified */
#define NDPI_FL_GIVEUP      0x0002  /* ndpi_detection_giveup() called */
#define NDPI_FL_HAS_PROTO   0x0004  /* reserved (unused) */
#define NDPI_FL_HAS_HOST    0x0008  /* reserved (unused) */
#define NDPI_FL_HAS_JA4     0x0010  /* reserved (unused) */
#define NDPI_FL_HAS_UA      0x0020  /* reserved (unused) */

typedef struct _packetinfo packetinfo;
typedef struct _connection connection;
struct _globalconfig;

int  ndpi_engine_init(struct _globalconfig *conf);
void ndpi_engine_destroy(struct _globalconfig *conf);
void ndpi_engine_process_packet(struct _globalconfig *conf, packetinfo *pi);
void ndpi_engine_free_flow(connection *cxt);

#endif /* HAVE_NDPI */
#endif /* NDPI_ENGINE_H */
