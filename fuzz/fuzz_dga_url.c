#include "ndpi_api.h"
#include "fuzz_common_code.h"

static struct ndpi_detection_module_struct *ndpi_struct = NULL;
static struct ndpi_flow_struct *ndpi_flow = NULL;

static char *path = NULL;

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  (void)argc;

  path = dirname(strdup(*argv[0])); /* No errors; no free! */
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  char *name;

  if (ndpi_struct == NULL) {
    fuzz_init_detection_module(&ndpi_struct, NULL, path);
    ndpi_flow = ndpi_calloc(1, sizeof(struct ndpi_flow_struct));
  }

  if (size == 0)
    return 0;

  name = ndpi_malloc(size + 1);
  if (name) {
    memcpy(name, data, size);
    name[size] = '\0';
    ndpi_check_dga_url_path(ndpi_struct, ndpi_flow, name);
    ndpi_free(name);
  }

  return 0;
}
