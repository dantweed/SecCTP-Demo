#ifndef HTTP_H
#define HTTP_H

#define ERROR_PAGE "<html><head><title>Error</title></head><body>Error</body></html>"
#define UNAUTH "<html><head><title>Authorization Failure</title></head><body>Invalid credentials supplied</body></html>"
#define WORKING "<html><head><title>Processing</title></head><body>Processing request...</body></html>"
#define PROCESSED "<html><head><title>Success</title></head><body>Payment submitted successfully</body></html>"

#define POSTBUFFERSIZE  512
#define GET 0
#define POST 1

#define PMT_KEY "pmtAmt"

struct connection_info_struct {
  int connectiontype;
  char *answerstring;
  struct MHD_PostProcessor *postprocessor;
};
#endif
