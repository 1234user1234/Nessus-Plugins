# Web-pages script discovery

include("compat.inc");

if(description)
{
    script_id(1020304);
    script_version("Version: 0.1");
    script_cvs_date("Date: 2019/11/27 15:28:12");

    script_name(english: "Web path search");
    script_summary(english: "Reports if WEB-pages was discovered on the remote host.");

    script_set_attribute(attribute:"synopsis", value: "WEB-pages was detected on the remote host.");
    script_set_attribute(attribute:"description", value: "WEB-pages was detected on the remote host.");
    script_set_attribute(attribute:"solution", value: "Restrict access to the web-pages, if desired.");
    script_set_attribute(attribute:"risk_factor", value: "Low");
    script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/26");
    script_set_attribute(attribute:"plugin_type", value:"remote");
    script_end_attributes();

    script_category(ACT_ATTACK);
    script_copyright(english:"This script is Copyright (C) Me");
    script_family(english: "Misc.");

    script_dependencies("http_version.nasl","webmirror.nasl");
#    script_exclude_keys("Settings/disable_cgi_scanning");
#    script_require_keys("Settings/enable_web_app_tests");
    script_require_ports("Services/www");

    script_timeout(1800);
    exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

#app = "Web-server";
global_var port;

port = get_http_port(default: 80);
if (! get_port_state(port)) exit(0, "Port "+port+" is closed.");

prefix_list = make_list("",".","_","~");

file_list = make_list("access","account","admin","administrator","app","archive","auth","backup","build","config","cmd","data","database","debug","default","dump","error","file","health","healthz","home","index","install","log","login","main","manage","metric","monitoring","password","project","public","search","server","server-status","setting","shell","site","status","test","tmp","update","upload","user","xml","xmlrpc");

# 's' for plural
extension_list = make_list("",".ashx",".asp",".aspx",".bak",".html",".inc",".ini",".json",".log",".php",".php~",".php.bak",".sql",".tar",".tar.gz",".tgz",".txt",".txt~",".xml",".zip","s");

suffix_list = make_list("","/","/%20","/?anything","#");

found_list = make_list();
found_ctr = 0;
high_severity = 0;
dirs = list_uniq(make_list(cgi_dirs(), ""));

postdata = 'test=test';

foreach dir (dirs)
{
    path = dir + '/';
    foreach prefix (prefix_list)
    {
        foreach file (file_list)
        {
		foreach extension (extension_list)
		{
			foreach suffix (suffix_list)
			{
				# path/ + . + admin + .php + /
				url = path + prefix + file + extension + suffix;
				res_get = http_send_recv3(
					method : 'GET',
					port : port,
					item : url,
					exit_on_fail : FALSE
				);
				if (res_get[0] =~ '^HTTP/[0-9.]+ +200')
				{
					found_list[found_ctr] = url + '\t\t:GET';
					found_ctr++;
				};
				res_post = http_send_recv3(
					port : port,
					method : 'POST',
					item : url,
					#content-type : "text/html",
					#data : postdata,
					exit_on_fail : FALSE
				);
				if (res_post[0] =~ '^HTTP/[0-9.]+ +200')
				{
					found_list[found_ctr] = url + '\t\t:POST';
					found_ctr++;
				};
			}
		}
	}
    }
}

report = "";
if (found_ctr > 0)
{
    if (report_verbosity > 0)
    {
        for (i = 0; i < found_ctr; i++)
        {
            url = found_list[i];
            report += 'URL\t\t: ' + build_url(port: port, qs: url) + '\n';
        }

    }

}

report = '\nThe following pages was detected on the remote host: \n\n' + report;
security_note(port:port, extra:report);
