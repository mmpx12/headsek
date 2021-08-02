package main

import (
	"context"
	"fmt"
	"github.com/mmpx12/optionparser"
	"net/http"
	"os"
	"strings"
	"time"
)

const version = "Version 0.1 (02-08-2021)"

type header struct {
	name        string
	surname     string
	description string
	deprecated  int // 0 no, 1 yes, 2 almost (acording to owasp)
}

var headers = []header{
	header{
		name:        "Strict-Transport-Security",
		surname:     "HSTS",
		description: "Helps to protect websites against protocol downgrade attacks and cookie hijacking. It allows web servers to declare that web browsers (or other complying user agents) should only interact with it using secure HTTPS connections, and never via the insecure HTTP protocol.",
		deprecated:  0,
	},
	header{
		name:        "Content-Security-Policy",
		surname:     "CSP",
		description: "CSP has significant impact on the way browsers render pages (e.g., inline JavaScript is disabled by default and must be explicitly allowed in the policy). CSP prevents a wide range of attacks, including cross-site scripting and other cross-site injections.",
		deprecated:  0,
	},
	header{
		name:        "X-Frame-Options",
		surname:     "XFO",
		description: "Improves the protection of web applications against clickjacking. It instructs the browser whether the content can be displayed within frames. The CSP frame-ancestors directive obsoletes the X-Frame-Options header. If a resource has both policies, the CSP frame-ancestors policy will be enforced and the X-Frame-Options policy will be ignored.",
		deprecated:  0,
	},
	header{
		name:        "X-Content-Type-Options",
		description: "Prevent the browser from interpreting files as a different MIME type to what is specified in the Content-Type HTTP header (e.g. treating text/plain as text/css).",
		deprecated:  0,
	},
	header{
		name:        "X-Permitted-Cross-Domain-Policies",
		description: "When clients request content hosted on a particular source domain and that content make requests directed towards a domain other than its own, the remote domain needs to host a cross-domain policy file that grants access to the source domain, allowing the client to continue the transaction. Normally a meta-policy is declared in the master policy file, but for those who can’t write to the root directory, they can also declare a meta-policy using the X-Permitted-Cross-Domain-Policies HTTP response header. ",
		deprecated:  0,
	},
	header{
		name:        "Referrer-Policy",
		description: "The Referrer-Policy HTTP header governs which referrer information, sent in the Referer header, should be included with requests made.",
		deprecated:  0,
	},
	header{
		name:        "Clear-Site-Data",
		description: "The Clear-Site-Data header clears browsing data (cookies, storage, cache) associated with the requesting website. It allows web developers to have more control over the data stored locally by a browser for their origins (source Mozilla MDN). This header is useful for example, during a logout process, in order to ensure that all stored content on the client side like cookies, storage and cache are removed.",
		deprecated:  0,
	},
	header{
		name:        "Cross-Origin-Embedder-Policy",
		surname:     "COEP",
		description: "Prevents a document from loading any cross-origin resources that don’t explicitly grant the document permission",
		deprecated:  0,
	},
	header{
		name:        "Cross-Origin-Resource-Policy",
		surname:     "CORP",
		description: "Allows to define a policy that lets web sites and applications opt in to protection against certain requests from other origins (such as those issued with elements like <script> and <img>), to mitigate speculative side-channel attacks, like Spectre, as well as Cross-Site Script Inclusion (XSSI) attacks",
		deprecated:  0,
	},
	header{
		name:        "Permissions-Policy",
		description: "Replaces the existing Feature-Policy header for controlling delegation of permissions and powerful features. The header uses a structured syntax, and allows sites to more tightly restrict which origins can be granted access to features",
		deprecated:  0,
	},
	header{
		name:        "Feature-Policy",
		description: "This header was split into Permissions-Policy and Document-Policy and will be considered deprecated once all impacted features are moved off of feature policy.\nAllows developers to selectively enable and disable use of various browser features and APIs.",
		deprecated:  2,
	},
	header{
		name:        "Expect-Ct",
		description: "The Expect-CT header is used by a server to indicate that browsers should evaluate connections to the host for Certificate Transparency compliance.",
		deprecated:  2,
	},
	header{
		name:        "Public-Key-Pins",
		surname:     "HPKP",
		description: "Security mechanism which allows HTTPS websites to resist impersonation by attackers using mis-issued or otherwise fraudulent certificates.",
		deprecated:  1,
	},
	header{
		name:        "X-Xss-Protection",
		description: "This header enables the cross-site scripting (XSS) filter in your browser. It is now deprecated and should be set to 0.",
		deprecated:  1,
	},
}

func check_header(res http.Header, j header, description bool) {
	var name string
	if j.surname != "" {
		name = j.name + " (" + j.surname + ")"
	} else {
		name = j.name
	}
	if _, ok := res[j.name]; ok {
		if j.name == "Content-Security-Policy" {
			if strings.Contains(strings.Join(res["Content-Security-Policy"], ""), "unsafe") {
				fmt.Println("\033[38;5;208m   • " + name + " \033[31mSET \033[48;5;208;1;38;5;0mMISCONFIGURED\033[0m")
				fmt.Println("\033[38;5;208m   ╰─[\033[36mINF0\033[38;5;208m] \033[36mFound unsafe that should not be use")
				return
			}
		} else if j.name == "X-Xss-Protection" {
			if strings.Contains(strings.Join(res["X-Xss-Protection"], ""), "1") {
				fmt.Println("\033[38;5;208m   • " + name + " \033[33mSET \033[48;5;196;1;38;5;7mDEPREACTAED\033[0m & \033[48;5;208;1;38;5;0mMISCONFIGURED\033[0m")
				fmt.Println("\033[38;5;208m   ╰─[\033[36mINF0\033[38;5;208m] \033[36mDeprecated and should be set to 0 if set (found: \"" + strings.Join(res["X-Xss-Protection"], "") + "\")")
				return
			} else {
				fmt.Println("\033[38;5;208m   • " + name + " \033[32mSET \033[48;5;208;1;38;5;0mDEPREACTAED\033[0m")
				return
			}
		}
		switch j.deprecated {
		case 0:
			fmt.Println("\033[38;5;208m   • " + name + " \033[32mSET \033[0m")
		case 1:
			fmt.Println("\033[38;5;208m   • " + name + " \033[31mSET \033[48;5;196;1;38;5;7mDEPRECATED\033[0m")
		case 2:
			fmt.Println("\033[38;5;208m   • " + name + " \033[33m SET \033[38;5;208m(ALSMOST DEPRECATED)\033[0m")
		}
	} else {
		switch j.deprecated {
		case 0:
			fmt.Println("\033[38;5;208m   • " + name + " \033[31mNOT SET \033[0m")
		case 1:
			fmt.Println("\033[38;5;208m   • " + name + " \033[32mNOT SET \033[38;5;208m(DEPRECATED)\033[0m")
		case 2:
			fmt.Println("\033[38;5;208m   • " + name + " \033[31mNOT SET \033[38;5;208m(ALMOST DEPRECATED)\033[0m")
		}
	}
	if description {
		fmt.Println("\033[33m   ╰─[Description]", j.description)
	}
}

func print_version() {
	fmt.Println(version)
	os.Exit(0)
}

func request(url, cookies, UserAgent, post string) http.Header {
	client := &http.Client{}
	ctx, cncl := context.WithTimeout(context.Background(), time.Second*5)
	defer cncl()
	var req *http.Request
	if post != "" {
		PostData := strings.NewReader(post)
		req, _ = http.NewRequestWithContext(ctx, "POST", url, PostData)
	} else {
		req, _ = http.NewRequestWithContext(ctx, "GET", url, nil)
	}

	if cookies != "" {
		req.Header.Set("Cookie", cookies)
	}

	if UserAgent != "" {
		req.Header.Add("User-Agent", UserAgent)
	} else {
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36")
	}

	resp, err := client.Do(req)
	if err != nil {
		error := err.Error()
		fmt.Println("\033[31mERROR:\033[33m\n" + error + "\033[0m")
		os.Exit(1)
	}
	return resp.Header
}

func main() {
	var nologo, description bool
	var url, UserAgent, post, cookies string
	op := optionparser.NewOptionParser()
	op.Banner = "Headsek: Security header analyzer\n\nUsage:\n"
	op.On("-d", "--description", "Print description under the result", &description)
	op.On("-n", "--nologo", "don't print banner", &nologo)
	op.On("-u", "--url URL", "set target URL (not mandatory if url is last parameter)", &url)
	op.On("-U", "--user-agent USER-AGENT", "set user-agent", &UserAgent)
	op.On("-p", "--post POST-DATA", "set post data (will use POST instead of GET)", &post)
	op.On("-c", "--cookies COOKIES", "set cookies", &cookies)
	op.On("-v", "--version", "show version", print_version)
	op.Exemple("# GET request\n      headsek -n -u https://exemple.com")
	op.Exemple("# POST request:\n      headsek -n -p \"whatever=1&somethingelse=yes\" https://exemple.com")
	op.Exemple("# Set cookie and user-agent\n      headsek -n -c \"sessionid=something;userid=1\" -U \"some user-agent\" https://exemple.com")
	op.Parse()
	op.Logo("headsek", "random", nologo)
	if strings.Join(op.Extra, "") != "" {
		url = strings.Join(op.Extra, "")
	}

	if url == "" {
		fmt.Println("ERROR: You should set an url\n")
		op.Help()
		os.Exit(1)
	} else if !strings.Contains(url, "http://") && !strings.Contains(url, "https://") {
		url = "http://" + url
	}

	resp := request(url, cookies, UserAgent, post)
	for _, j := range headers {
		check_header(resp, j, description)
	}
}
