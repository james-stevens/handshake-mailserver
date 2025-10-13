
// regex for an FQDN domain name
const fqdnCheck = /^([a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?\.)+[a-zA-Z0-9][a-zA-Z0-9-]{0,61}/
const tldCheck = /^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}/

// regex for adding a host name
const hostnameCheck = /^([a-zA-Z0-9_*]|[a-zA-Z0-9_][a-zA-Z0-9\-_]*[a-zA-Z0-9_])(\.([a-zA-Z0-9_]|[a-zA-Z0-9_][a-zA-Z0-9\-_]*[a-zA-Z0-9_]))*$/

const valid_email = /^(([^<>()[\]\\.,;:\s@\"]+(\.[^<>()[\]\\.,;:\s@\"]+)*)|(\".+\"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;

const pow10 = { 0:1, 1:10, 2:100, 3:1000, 4:10000, 5:100000, 6:1000000, 7:10000000, 8:100000000, 9:1000000000, 10:10000000000 };
function from_float(amount) { return Math.round(parseFloat(amount)*pow10[gbl.config.currency.decimal]); }


function callApi(sfx,callback,inData)
{
	unerrMsg();
	document.body.style.cursor="progress";
	let show_timer = true;
	if ((inData)&&("show_timer" in inData)) show_timer = inData.show_timer;
	if (show_timer) elm.topMsg.innerHTML = gbl.loading;

	function default_callback(ok,reply) { console.log("CALLBACK:",ok,reply); return; }
	if (!callback) callback = default_callback;

	function we_are_done(ok,reply)
	{
		document.body.style.cursor="auto";
		if (show_timer) elm.topMsg.innerHTML = "";
		return callback(ok,reply);
	}

	function check_session(headers)
	{
		let got_ses = false;
		headers.forEach((val, key) => {
			if (key=="x-session-code") {
				got_ses = true;
				if (!("session" in ctx)) {
					window.localStorage.setItem("session",val);
					ctx.session = val;
					loggedIn();
					}
				}
			});

		if ((!got_ses)&&("session" in ctx)) {
			window.localStorage.removeItem("session");
			ctx = {};
			loggedOut();
			}
	}

	if (debugAPI) { console.log("API>>>",sfx); console.log("API>>>",inData); }

	let url = `${window.location.origin}/wmapi/${sfx}`;
	if (gbl.url_prefix)
		url = `${window.location.origin}${gbl.url_prefix}${sfx}`;
	if (sfx.slice(0,1)=="/")
		url = `${window.location.origin}${sfx}`;

	let okResp = 200;
	let httpCmd = {
		headers: {
			"Content-type" : "application/json; charset=UTF-8",
			"Accept" : "application/json; charset=UTF-8"
			},
		method: 'GET' };

	if (inData != null) {
		if ("json" in inData) {
			httpCmd.body = JSON.stringify(inData.json);
			httpCmd.headers["Content-type"] = "application/json; charset=UTF-8";
			httpCmd.method = "POST";
			}
		if ("okResp" in inData) okResp = inData.okResp;
		if ("method" in inData) httpCmd.method = inData.method;
		}

	if ("session" in ctx) {
		httpCmd.headers["X-Session-Code"] = ctx.session
	} else {
		let s = window.localStorage.getItem("session");
		if (s != null) {
			httpCmd.headers["X-Session-Code"] = s;
			ctx.session = s;
			}
		}
	if (debugAPI) { 
		console.log("OUT-HEAD",httpCmd.headers);
		console.log("OUT-METHOD",httpCmd.method);
		}

	fetch(url,httpCmd).then(response => {
		if (response.status != okResp) {
			response.text().then(
				data => {
					if (debugAPI) {
						console.log("API>>> Resp/BAD",data);
						console.log("API>>> BAD",response.status,response.statusText);
						}
					if (response.status != 299) return we_are_done(false,{"error":"Unexecpted System Error"});
					check_session(response.headers);
					try {
						return we_are_done(false,JSON.parse(data));
					} catch {
						return we_are_done(false,{"error":data});
						}
					},
				() => errMsg(`ERROR:2: ${response.status} ${response.statusText}`)
				);
			return;
			}
		else {
			response.text().then(data => {
				if (debugAPI) console.log("API>>> Resp/OK",data);
				check_session(response.headers);

				if (debugAPI) console.log("API>>> OK",response.status,response.statusText);

				if ((inData != null)&&(inData.noData)) {
					return we_are_done(true,true);
				} else {
					let param = data;
					try {
						param = JSON.parse(data); }
					catch {
						param = data; }

					return we_are_done(true,param);
					}
				});
			}
		})
		.catch((err) => {
			we_are_done(false,{"error":"Server connection error"})
			} );
}



function policy(name,val)
{
	if (!("config" in gbl)) return val;
	if (!("policy" in gbl.config)) return val;
	if (!(name in gbl.config.policy)) return val;
	return gbl.config.policy[name];
}



function fromPuny(fqdn)
{
	if ((fqdn.substr(0,4)=="xn--")||(fqdn.indexOf(".xn--") > 0))
		return toUnicode(fqdn);
	return fqdn;
}



function btn(call,txt,hlp,sz)
{
	let ex=""
	if (sz != null) ex = `style='width: ${sz}px;'`
	return `<span ${ex} tabindex=0 title="${hlp}" class=myBtn onClick="${call}; return false;">${txt}</span>`;
}


function supported_tld(fqdn)
{
	if ((pos = fqdn.indexOf(".")) < 0) return false;
	return (fqdn.substr(pos+1) in gbl.config.ok_tlds);
}




function def_errMsg(msg,reply,tagged_elm)
{
	if ((reply)&&(reply.error)) errMsg(reply.error,tagged_elm); else errMsg(msg,tagged_elm);
}


function unerrMsg()
{
	let t1 = elm.myMsgPop.innerHTML;
	let t2 = ctx.lastErrMsg;
	if (t2 == null) t2 = "";
	if (t1 == t2) elm.myMsgPop.className = "msgPop msgPopNo";
	delete ctx.lastErrMsg;
	if (ctx.err_msg_tout) clearTimeout(ctx.err_msg_tout);
	delete ctx.err_msg_tout;
}



function errMsg(txt,tagged_elm)
{
	let hang_elm = null;
	if (tagged_elm in elm) hang_elm = elm[tagged_elm];
	else hang_elm = document.getElementById(tagged_elm);
	if (!hang_elm) hang_elm = elm.userInfo;

	let m = elm.myMsgPop;
	m.style.width = "auto";
	if (txt.slice(0,1)!="&") txt = gbl.warn + " " + txt;
	m.innerHTML = "&nbsp;"+txt+"&nbsp;";

	let p_box = hang_elm.getBoundingClientRect();
	let m_box = m.getBoundingClientRect();
	let m_width = m_box.width;

	if (m_box.width < p_box.width) {
		m.style.width = p_box.width + "px";
		m_width = p_box.width;
		}
	let centre = p_box.x + (p_box.width/2);
	let x_pos = centre - (m_width / 2)
	m.style.left = x_pos + "px";
	m.style.top = p_box.y + p_box.height + "px";

	m.className = 'msgPop msgPopYes';
	ctx.lastErrMsg = m.innerHTML;
	ctx.err_msg_tout = setTimeout(unerrMsg,2500);

	return false;
}



function hasIDN(name)
{
	if (name.slice(0,4)=="xn--") return true;
	if (name.indexOf(".xn--") > 0) return true
	return false;
}




function clean_host_name(dom_name,hostname)
{
	if (!hostname) return "";
	if (hostname==dom_name) return '@';
	if (hostname.slice(-1*dom_name.length)==dom_name) hostname = hostname.slice(0,-1*(dom_name.length+1))
	if (hasIDN(hostname)) hostname = fromPuny(hostname);
	return hostname;
}


function form_prompt(txt) { return `<tr><td class=formPrompt>${txt} :</td><td>`; }
function settings_prompt(txt) { return `<tr><td class=promptCell>${txt} :</td><td>`; }


function settings_header(title,spacer)
{
    let x = "";
    if (!spacer) x = gbl.settings_spacer;
    x += `<tr><td class=settingsBanner>${title}</td></tr><tr><td>`;
    return x;
}



function generic_popup_btn(config)
{
    /* config: width, style, title, name, label, internal(), param */
    let style_width="",pop_style="";
    if ("width" in config) style_width = `style='width: ${config["width"]}px;'`;
    if ("style" in config) pop_style = `style='${config["style"]}'`;

    let timeout = 30000;
    if ("timeout" in config) timeout = config.timeout;

    let x = `<div class="popup">`;
    x += `<span ${style_width}75px;' tabindex=0 title="${config["title"]}" `;
    x += `class=myBtn onClick="togglePopUp('${config["name"]}',${timeout});">${config["label"]}</span>`;
    x += `<span class="popuptext" ${pop_style} id="${config["name"]}">`;
    x += config["internal"](config["param"]);
    return x + `</span></div>`;
}



function add_payment_script(module) {
    let s = document.createElement('script');
    s.setAttribute("src", "/"+module+".js" );
    s.setAttribute("type", 'text/javascript');
    s.onload = () => { eval(module+"_startup()"); };
    document.body.appendChild( s );
}



function rand_tag(want_char)
{
	if (!want_char) want_char = 30
	let myar = new Uint8Array(10);
    return btoa(window.crypto.getRandomValues(myar)).slice(0,want_char);
}



function pretty_prompt(tag)
{
    let s = tag.split("_");
    for(let i in s)
        s[i] = s[i][0].toUpperCase() + s[i].substr(1);
    return s.join(" ");
}



function local_dt(date_time)
{
	d = new Date(date_time+" UTC");
	return d.toLocaleString();
}



function local_date(date_time)
{
	d = new Date(date_time+" UTC");
	return d.toLocaleDateString();
}
