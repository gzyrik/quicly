#include "httplib.h"
static const char* _help = "help";
int main()
{
    httplib::Server websrv;
    websrv.Get("/", [](const httplib::Request& /*req*/, httplib::Response& res) {
        res.set_content(_help, "text/plain");
        res.set_header("alt-svc", "quic=\":443\"; ma=2592000; v=\"44,43,39,35\"");
    });
    _svr.listen("*", 443);
}
