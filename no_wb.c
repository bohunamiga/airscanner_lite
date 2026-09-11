#include <workbench/startup.h>

/* Bezpieczna, uodporniona zaślepka zapobiegająca ładowaniu wadliwego kodu z libautoinit.a */
struct WBStartup *WBenchMsg = NULL;