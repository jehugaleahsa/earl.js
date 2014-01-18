// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

var earl = (function () {

	function isArray(ar) {
	  return Array.isArray(ar);
	}

	function isNull(arg) {
	  return arg === null;
	}

	function isNullOrUndefined(arg) {
	  return arg == null;
	}

	function isObject(arg) {
		return typeof arg === 'object' && arg !== null
	}

	function isString(arg) {
		return typeof arg === 'string';
	}

	function isNumber(arg) {
	  return typeof arg === 'number';
	}

	function isBoolean(arg) {
	  return typeof arg === 'boolean';
	}

	// If obj.hasOwnProperty has been overridden, then calling
	// obj.hasOwnProperty(prop) will break.
	// See: https://github.com/joyent/node/issues/1707
	function hasOwnProperty(obj, prop) {
	  return Object.prototype.hasOwnProperty.call(obj, prop);
	}

	function charCode(c) {
	  return c.charCodeAt(0);
	}

	var QueryString = {};

	// a safe fast alternative to decodeURIComponent
	QueryString.unescapeBuffer = function(s, decodeSpaces) {
	  var out = new Buffer(s.length);
	  var state = 'CHAR'; // states: CHAR, HEX0, HEX1
	  var n, m, hexchar;

	  for (var inIndex = 0, outIndex = 0; inIndex <= s.length; inIndex++) {
		var c = s.charCodeAt(inIndex);
		switch (state) {
		  case 'CHAR':
			switch (c) {
			  case charCode('%'):
				n = 0;
				m = 0;
				state = 'HEX0';
				break;
			  case charCode('+'):
				if (decodeSpaces) c = charCode(' ');
				// pass thru
			  default:
				out[outIndex++] = c;
				break;
			}
			break;

		  case 'HEX0':
			state = 'HEX1';
			hexchar = c;
			if (charCode('0') <= c && c <= charCode('9')) {
			  n = c - charCode('0');
			} else if (charCode('a') <= c && c <= charCode('f')) {
			  n = c - charCode('a') + 10;
			} else if (charCode('A') <= c && c <= charCode('F')) {
			  n = c - charCode('A') + 10;
			} else {
			  out[outIndex++] = charCode('%');
			  out[outIndex++] = c;
			  state = 'CHAR';
			  break;
			}
			break;

		  case 'HEX1':
			state = 'CHAR';
			if (charCode('0') <= c && c <= charCode('9')) {
			  m = c - charCode('0');
			} else if (charCode('a') <= c && c <= charCode('f')) {
			  m = c - charCode('a') + 10;
			} else if (charCode('A') <= c && c <= charCode('F')) {
			  m = c - charCode('A') + 10;
			} else {
			  out[outIndex++] = charCode('%');
			  out[outIndex++] = hexchar;
			  out[outIndex++] = c;
			  break;
			}
			out[outIndex++] = 16 * n + m;
			break;
		}
	  }

	  // TODO support returning arbitrary buffers.

	  return out.slice(0, outIndex - 1);
	};


	QueryString.unescape = function(s, decodeSpaces) {
	  return QueryString.unescapeBuffer(s, decodeSpaces).toString();
	};


	QueryString.escape = function(str) {
	  return encodeURIComponent(str);
	};

	var stringifyPrimitive = function(v) {
	  if (isString(v))
		return v;
	  if (isBoolean(v))
		return v ? 'true' : 'false';
	  if (isNumber(v))
		return isFinite(v) ? v : '';
	  return '';
	};


	QueryString.stringify = QueryString.encode = function(obj, sep, eq) {
	  sep = sep || '&';
	  eq = eq || '=';
	  if (isNull(obj)) {
		obj = undefined;
	  }

	  if (isObject(obj)) {
		return Object.keys(obj).map(function(k) {
		  var ks = QueryString.escape(stringifyPrimitive(k)) + eq;
		  if (isArray(obj[k])) {
			return obj[k].map(function(v) {
			  return ks + QueryString.escape(stringifyPrimitive(v));
			}).join(sep);
		  } else {
			return ks + QueryString.escape(stringifyPrimitive(obj[k]));
		  }
		}).join(sep);

	  }
	  return '';
	};

	// Parse a key=val string.
	QueryString.parse = QueryString.decode = function(qs, sep, eq, options) {
	  sep = sep || '&';
	  eq = eq || '=';
	  var obj = {};

	  if (!isString(qs) || qs.length === 0) {
		return obj;
	  }

	  var regexp = /\+/g;
	  qs = qs.split(sep);

	  var maxKeys = 1000;
	  if (options && isNumber(options.maxKeys)) {
		maxKeys = options.maxKeys;
	  }

	  var len = qs.length;
	  // maxKeys <= 0 means that we should not limit keys count
	  if (maxKeys > 0 && len > maxKeys) {
		len = maxKeys;
	  }

	  for (var i = 0; i < len; ++i) {
		var x = qs[i].replace(regexp, '%20'),
			idx = x.indexOf(eq),
			kstr, vstr, k, v;

		if (idx >= 0) {
		  kstr = x.substr(0, idx);
		  vstr = x.substr(idx + 1);
		} else {
		  kstr = x;
		  vstr = '';
		}

		try {
		  k = decodeURIComponent(kstr);
		  v = decodeURIComponent(vstr);
		} catch (e) {
		  k = QueryString.unescape(kstr, true);
		  v = QueryString.unescape(vstr, true);
		}

		if (!hasOwnProperty(obj, k)) {
		  obj[k] = v;
		} else if (isArray(obj[k])) {
		  obj[k].push(v);
		} else {
		  obj[k] = [obj[k], v];
		}
	  }

	  return obj;
	};

	function Url() {
	  this.protocol = null;
	  this.slashes = null;
	  this.auth = null;
	  this.host = null;
	  this.port = null;
	  this.hostname = null;
	  this.hash = null;
	  this.search = null;
	  this.query = null;
	  this.pathname = null;
	  this.path = null;
	  this.href = null;
	}

	// Reference: RFC 3986, RFC 1808, RFC 2396

	// define these here so at least they only have to be
	// compiled once on the first module load.
	var protocolPattern = /^([a-z0-9.+-]+:)/i,
		portPattern = /:[0-9]*$/,

		// RFC 2396: characters reserved for delimiting URLs.
		// We actually just auto-escape these.
		delims = ['<', '>', '"', '`', ' ', '\r', '\n', '\t'],

		// RFC 2396: characters not allowed for various reasons.
		unwise = ['{', '}', '|', '\\', '^', '`'].concat(delims),

		// Allowed by RFCs, but cause of XSS attacks.  Always escape these.
		autoEscape = ['\''].concat(unwise),
		// Characters that are never ever allowed in a hostname.
		// Note that any invalid chars are also handled, but these
		// are the ones that are *expected* to be seen, so we fast-path
		// them.
		nonHostChars = ['%', '/', '?', ';', '#'].concat(autoEscape),
		hostEndingChars = ['/', '?', '#'],
		hostnameMaxLen = 255,
		hostnamePartPattern = /^[a-z0-9A-Z_-]{0,63}$/,
		hostnamePartStart = /^([a-z0-9A-Z_-]{0,63})(.*)$/,
		// protocols that can allow "unsafe" and "unwise" chars.
		unsafeProtocol = {
		  'javascript': true,
		  'javascript:': true
		},
		// protocols that never have a hostname.
		hostlessProtocol = {
		  'javascript': true,
		  'javascript:': true
		},
		// protocols that always contain a // bit.
		slashedProtocol = {
		  'http': true,
		  'https': true,
		  'ftp': true,
		  'gopher': true,
		  'file': true,
		  'http:': true,
		  'https:': true,
		  'ftp:': true,
		  'gopher:': true,
		  'file:': true
		},
		querystring = QueryString

	function urlParse(url, parseQueryString, slashesDenoteHost) {
	  if (url && isObject(url) && url instanceof Url) return url;

	  var u = new Url;
	  u.parse(url, parseQueryString, slashesDenoteHost);
	  return u;
	}

	Url.prototype.parse = function(url, parseQueryString, slashesDenoteHost) {
	  if (!isString(url)) {
		throw new TypeError("Parameter 'url' must be a string, not " + typeof url);
	  }

	  var rest = url;

	  // trim before proceeding.
	  // This is to support parse stuff like "  http://foo.com  \n"
	  rest = rest.trim();

	  var proto = protocolPattern.exec(rest);
	  if (proto) {
		proto = proto[0];
		var lowerProto = proto.toLowerCase();
		this.protocol = lowerProto;
		rest = rest.substr(proto.length);
	  }

	  // figure out if it's got a host
	  // user@server is *always* interpreted as a hostname, and url
	  // resolution will treat //foo/bar as host=foo,path=bar because that's
	  // how the browser resolves relative URLs.
	  if (slashesDenoteHost || proto || rest.match(/^\/\/[^@\/]+@[^@\/]+/)) {
		var slashes = rest.substr(0, 2) === '//';
		if (slashes && !(proto && hostlessProtocol[proto])) {
		  rest = rest.substr(2);
		  this.slashes = true;
		}
	  }

	  if (!hostlessProtocol[proto] &&
		  (slashes || (proto && !slashedProtocol[proto]))) {

		// there's a hostname.
		// the first instance of /, ?, ;, or # ends the host.
		//
		// If there is an @ in the hostname, then non-host chars *are* allowed
		// to the left of the last @ sign, unless some host-ending character
		// comes *before* the @-sign.
		// URLs are obnoxious.
		//
		// ex:
		// http://a@b@c/ => user:a@b host:c
		// http://a@b?@c => user:a host:c path:/?@c

		// v0.12 TODO(isaacs): This is not quite how Chrome does things.
		// Review our test case against browsers more comprehensively.

		// find the first instance of any hostEndingChars
		var hostEnd = -1;
		for (var i = 0; i < hostEndingChars.length; i++) {
		  var hec = rest.indexOf(hostEndingChars[i]);
		  if (hec !== -1 && (hostEnd === -1 || hec < hostEnd))
			hostEnd = hec;
		}

		// at this point, either we have an explicit point where the
		// auth portion cannot go past, or the last @ char is the decider.
		var auth, atSign;
		if (hostEnd === -1) {
		  // atSign can be anywhere.
		  atSign = rest.lastIndexOf('@');
		} else {
		  // atSign must be in auth portion.
		  // http://a@b/c@d => host:b auth:a path:/c@d
		  atSign = rest.lastIndexOf('@', hostEnd);
		}

		// Now we have a portion which is definitely the auth.
		// Pull that off.
		if (atSign !== -1) {
		  auth = rest.slice(0, atSign);
		  rest = rest.slice(atSign + 1);
		  this.auth = decodeURIComponent(auth);
		}

		// the host is the remaining to the left of the first non-host char
		hostEnd = -1;
		for (var i = 0; i < nonHostChars.length; i++) {
		  var hec = rest.indexOf(nonHostChars[i]);
		  if (hec !== -1 && (hostEnd === -1 || hec < hostEnd))
			hostEnd = hec;
		}
		// if we still have not hit it, then the entire thing is a host.
		if (hostEnd === -1)
		  hostEnd = rest.length;

		this.host = rest.slice(0, hostEnd);
		rest = rest.slice(hostEnd);

		// pull out port.
		this.parseHost();

		// we've indicated that there is a hostname,
		// so even if it's empty, it has to be present.
		this.hostname = this.hostname || '';

		// if hostname begins with [ and ends with ]
		// assume that it's an IPv6 address.
		var ipv6Hostname = this.hostname[0] === '[' &&
			this.hostname[this.hostname.length - 1] === ']';

		// validate a little.
		if (!ipv6Hostname) {
		  var hostparts = this.hostname.split(/\./);
		  for (var i = 0, l = hostparts.length; i < l; i++) {
			var part = hostparts[i];
			if (!part) continue;
			if (!part.match(hostnamePartPattern)) {
			  var newpart = '';
			  for (var j = 0, k = part.length; j < k; j++) {
				if (part.charCodeAt(j) > 127) {
				  // we replace non-ASCII char with a temporary placeholder
				  // we need this to make sure size of hostname is not
				  // broken by replacing non-ASCII by nothing
				  newpart += 'x';
				} else {
				  newpart += part[j];
				}
			  }
			  // we test again with ASCII char only
			  if (!newpart.match(hostnamePartPattern)) {
				var validParts = hostparts.slice(0, i);
				var notHost = hostparts.slice(i + 1);
				var bit = part.match(hostnamePartStart);
				if (bit) {
				  validParts.push(bit[1]);
				  notHost.unshift(bit[2]);
				}
				if (notHost.length) {
				  rest = '/' + notHost.join('.') + rest;
				}
				this.hostname = validParts.join('.');
				break;
			  }
			}
		  }
		}

		if (this.hostname.length > hostnameMaxLen) {
		  this.hostname = '';
		} else {
		  // hostnames are always lower case.
		  this.hostname = this.hostname.toLowerCase();
		}

		if (!ipv6Hostname) {
		  // IDNA Support: Returns a puny coded representation of "domain".
		  // It only converts the part of the domain name that
		  // has non ASCII characters. I.e. it dosent matter if
		  // you call it with a domain that already is in ASCII.
		  var domainArray = this.hostname.split('.');
		  var newOut = [];
		  for (var i = 0; i < domainArray.length; ++i) {
			var s = domainArray[i];
			newOut.push(s);
		  }
		  this.hostname = newOut.join('.');
		}

		var p = this.port ? ':' + this.port : '';
		var h = this.hostname || '';
		this.host = h + p;
		this.href += this.host;

		// strip [ and ] from the hostname
		// the host field still retains them, though
		if (ipv6Hostname) {
		  this.hostname = this.hostname.substr(1, this.hostname.length - 2);
		  if (rest[0] !== '/') {
			rest = '/' + rest;
		  }
		}
	  }

	  // now rest is set to the post-host stuff.
	  // chop off any delim chars.
	  // if (!unsafeProtocol[lowerProto]) {

		// // First, make 100% sure that any "autoEscape" chars get
		// // escaped, even if encodeURIComponent doesn't think they
		// // need to be.
		// for (var i = 0, l = autoEscape.length; i < l; i++) {
		  // var ae = autoEscape[i];
		  // var esc = encodeURIComponent(ae);
		  // if (esc === ae) {
			// esc = escape(ae);
		  // }
		  // rest = rest.split(ae).join(esc);
		// }
	  // }


	  // chop off from the tail first.
	  var hash = rest.indexOf('#');
	  if (hash !== -1) {
		// got a fragment string.
		this.hash = rest.substr(hash);
		rest = rest.slice(0, hash);
	  }
	  var qm = rest.indexOf('?');
	  if (qm !== -1) {
		this.search = rest.substr(qm);
		this.query = rest.substr(qm + 1);
		if (parseQueryString) {
		  this.query = querystring.parse(this.query);
		}
		rest = rest.slice(0, qm);
	  } else if (parseQueryString) {
		// no query string, but parseQueryString still requested
		this.search = '';
		this.query = {};
	  }
	  if (rest) this.pathname = rest;
	  if (slashedProtocol[lowerProto] &&
		  this.hostname && !this.pathname) {
		this.pathname = '/';
	  }

	  //to support http.request
	  if (this.pathname || this.search) {
		var p = this.pathname || '';
		var s = this.search || '';
		this.path = p + s;
	  }

	  // finally, reconstruct the href based on what has been validated.
	  this.href = this.format();
	  return this;
	};

	// format a parsed object into a url string
	function urlFormat(obj) {
	  // ensure it's an object, and not a string url.
	  // If it's an obj, this is a no-op.
	  // this way, you can call url_format() on strings
	  // to clean up potentially wonky urls.
	  if (isString(obj)) obj = urlParse(obj);
	  if (!(obj instanceof Url)) return Url.prototype.format.call(obj);
	  return obj.format();
	}

	Url.prototype.format = function() {
	  var auth = this.auth || '';
	  if (auth) {
		auth = encodeURIComponent(auth);
		auth = auth.replace(/%3A/i, ':');
		auth += '@';
	  }

	  var protocol = this.protocol || '',
		  pathname = this.pathname || '',
		  hash = this.hash || '',
		  host = false,
		  query = '';

	  if (this.host) {
		host = auth + this.host;
	  } else if (this.hostname) {
		host = auth + (this.hostname.indexOf(':') === -1 ?
			this.hostname :
			'[' + this.hostname + ']');
		if (this.port) {
		  host += ':' + this.port;
		}
	  }

	  if (this.query &&
		  isObject(this.query) &&
		  Object.keys(this.query).length) {
		query = querystring.stringify(this.query);
	  }

	  var search = this.search || (query && ('?' + query)) || '';

	  if (protocol && protocol.substr(-1) !== ':') protocol += ':';

	  // only the slashedProtocols get the //.  Not mailto:, xmpp:, etc.
	  // unless they had them to begin with.
	  if (this.slashes ||
		  (!protocol || slashedProtocol[protocol]) && host !== false) {
		host = '//' + (host || '');
		if (pathname && pathname.charAt(0) !== '/') pathname = '/' + pathname;
	  } else if (!host) {
		host = '';
	  }

	  if (hash && hash.charAt(0) !== '#') hash = '#' + hash;
	  if (search && search.charAt(0) !== '?') search = '?' + search;

	  pathname = pathname.replace(/[?#]/g, function(match) {
		return encodeURIComponent(match);
	  });
	  search = search.replace('#', '%23');

	  return protocol + host + pathname + search + hash;
	};

	function urlResolve(source, relative) {
	  return urlParse(source, false, true).resolve(relative);
	}

	Url.prototype.resolve = function(relative) {
	  return this.resolveObject(urlParse(relative, false, true)).format();
	};

	function urlResolveObject(source, relative) {
	  if (!source) return relative;
	  return urlParse(source, false, true).resolveObject(relative);
	}

	Url.prototype.resolveObject = function(relative) {
	  if (isString(relative)) {
		var rel = new Url();
		rel.parse(relative, false, true);
		relative = rel;
	  }

	  var result = new Url();
	  Object.keys(this).forEach(function(k) {
		result[k] = this[k];
	  }, this);

	  // hash is always overridden, no matter what.
	  // even href="" will remove it.
	  result.hash = relative.hash;

	  // if the relative url is empty, then there's nothing left to do here.
	  if (relative.href === '') {
		result.href = result.format();
		return result;
	  }

	  // hrefs like //foo/bar always cut to the protocol.
	  if (relative.slashes && !relative.protocol) {
		// take everything except the protocol from relative
		Object.keys(relative).forEach(function(k) {
		  if (k !== 'protocol')
			result[k] = relative[k];
		});

		//urlParse appends trailing / to urls like http://www.example.com
		if (slashedProtocol[result.protocol] &&
			result.hostname && !result.pathname) {
		  result.path = result.pathname = '/';
		}

		result.href = result.format();
		return result;
	  }

	  if (relative.protocol && relative.protocol !== result.protocol) {
		// if it's a known url protocol, then changing
		// the protocol does weird things
		// first, if it's not file:, then we MUST have a host,
		// and if there was a path
		// to begin with, then we MUST have a path.
		// if it is file:, then the host is dropped,
		// because that's known to be hostless.
		// anything else is assumed to be absolute.
		if (!slashedProtocol[relative.protocol]) {
		  Object.keys(relative).forEach(function(k) {
			result[k] = relative[k];
		  });
		  result.href = result.format();
		  return result;
		}

		result.protocol = relative.protocol;
		if (!relative.host && !hostlessProtocol[relative.protocol]) {
		  var relPath = (relative.pathname || '').split('/');
		  while (relPath.length && !(relative.host = relPath.shift()));
		  if (!relative.host) relative.host = '';
		  if (!relative.hostname) relative.hostname = '';
		  if (relPath[0] !== '') relPath.unshift('');
		  if (relPath.length < 2) relPath.unshift('');
		  result.pathname = relPath.join('/');
		} else {
		  result.pathname = relative.pathname;
		}
		result.search = relative.search;
		result.query = relative.query;
		result.host = relative.host || '';
		result.auth = relative.auth;
		result.hostname = relative.hostname || relative.host;
		result.port = relative.port;
		// to support http.request
		if (result.pathname || result.search) {
		  var p = result.pathname || '';
		  var s = result.search || '';
		  result.path = p + s;
		}
		result.slashes = result.slashes || relative.slashes;
		result.href = result.format();
		return result;
	  }

	  var isSourceAbs = (result.pathname && result.pathname.charAt(0) === '/'),
		  isRelAbs = (
			  relative.host ||
			  relative.pathname && relative.pathname.charAt(0) === '/'
		  ),
		  mustEndAbs = (isRelAbs || isSourceAbs ||
						(result.host && relative.pathname)),
		  removeAllDots = mustEndAbs,
		  srcPath = result.pathname && result.pathname.split('/') || [],
		  relPath = relative.pathname && relative.pathname.split('/') || [],
		  psychotic = result.protocol && !slashedProtocol[result.protocol];

	  // if the url is a non-slashed url, then relative
	  // links like ../.. should be able
	  // to crawl up to the hostname, as well.  This is strange.
	  // result.protocol has already been set by now.
	  // Later on, put the first path part into the host field.
	  if (psychotic) {
		result.hostname = '';
		result.port = null;
		if (result.host) {
		  if (srcPath[0] === '') srcPath[0] = result.host;
		  else srcPath.unshift(result.host);
		}
		result.host = '';
		if (relative.protocol) {
		  relative.hostname = null;
		  relative.port = null;
		  if (relative.host) {
			if (relPath[0] === '') relPath[0] = relative.host;
			else relPath.unshift(relative.host);
		  }
		  relative.host = null;
		}
		mustEndAbs = mustEndAbs && (relPath[0] === '' || srcPath[0] === '');
	  }

	  if (isRelAbs) {
		// it's absolute.
		result.host = (relative.host || relative.host === '') ?
					  relative.host : result.host;
		result.hostname = (relative.hostname || relative.hostname === '') ?
						  relative.hostname : result.hostname;
		result.search = relative.search;
		result.query = relative.query;
		srcPath = relPath;
		// fall through to the dot-handling below.
	  } else if (relPath.length) {
		// it's relative
		// throw away the existing file, and take the new path instead.
		if (!srcPath) srcPath = [];
		srcPath.pop();
		srcPath = srcPath.concat(relPath);
		result.search = relative.search;
		result.query = relative.query;
	  } else if (!isNullOrUndefined(relative.search)) {
		// just pull out the search.
		// like href='?foo'.
		// Put this after the other two cases because it simplifies the booleans
		if (psychotic) {
		  result.hostname = result.host = srcPath.shift();
		  //occationaly the auth can get stuck only in host
		  //this especialy happens in cases like
		  //url.resolveObject('mailto:local1@domain1', 'local2@domain2')
		  var authInHost = result.host && result.host.indexOf('@') > 0 ?
						   result.host.split('@') : false;
		  if (authInHost) {
			result.auth = authInHost.shift();
			result.host = result.hostname = authInHost.shift();
		  }
		}
		result.search = relative.search;
		result.query = relative.query;
		//to support http.request
		if (!isNull(result.pathname) || !isNull(result.search)) {
		  result.path = (result.pathname ? result.pathname : '') +
						(result.search ? result.search : '');
		}
		result.href = result.format();
		return result;
	  }

	  if (!srcPath.length) {
		// no path at all.  easy.
		// we've already handled the other stuff above.
		result.pathname = null;
		//to support http.request
		if (result.search) {
		  result.path = '/' + result.search;
		} else {
		  result.path = null;
		}
		result.href = result.format();
		return result;
	  }

	  // if a url ENDs in . or .., then it must get a trailing slash.
	  // however, if it ends in anything else non-slashy,
	  // then it must NOT get a trailing slash.
	  var last = srcPath.slice(-1)[0];
	  var hasTrailingSlash = (
		  (result.host || relative.host) && (last === '.' || last === '..') ||
		  last === '');

	  // strip single dots, resolve double dots to parent dir
	  // if the path tries to go above the root, `up` ends up > 0
	  var up = 0;
	  for (var i = srcPath.length; i >= 0; i--) {
		last = srcPath[i];
		if (last == '.') {
		  srcPath.splice(i, 1);
		} else if (last === '..') {
		  srcPath.splice(i, 1);
		  up++;
		} else if (up) {
		  srcPath.splice(i, 1);
		  up--;
		}
	  }

	  // if the path is allowed to go above the root, restore leading ..s
	  if (!mustEndAbs && !removeAllDots) {
		for (; up--; up) {
		  srcPath.unshift('..');
		}
	  }

	  if (mustEndAbs && srcPath[0] !== '' &&
		  (!srcPath[0] || srcPath[0].charAt(0) !== '/')) {
		srcPath.unshift('');
	  }

	  if (hasTrailingSlash && (srcPath.join('/').substr(-1) !== '/')) {
		srcPath.push('');
	  }

	  var isAbsolute = srcPath[0] === '' ||
		  (srcPath[0] && srcPath[0].charAt(0) === '/');

	  // put the host back
	  if (psychotic) {
		result.hostname = result.host = isAbsolute ? '' :
										srcPath.length ? srcPath.shift() : '';
		//occationaly the auth can get stuck only in host
		//this especialy happens in cases like
		//url.resolveObject('mailto:local1@domain1', 'local2@domain2')
		var authInHost = result.host && result.host.indexOf('@') > 0 ?
						 result.host.split('@') : false;
		if (authInHost) {
		  result.auth = authInHost.shift();
		  result.host = result.hostname = authInHost.shift();
		}
	  }

	  mustEndAbs = mustEndAbs || (result.host && srcPath.length);

	  if (mustEndAbs && !isAbsolute) {
		srcPath.unshift('');
	  }

	  if (!srcPath.length) {
		result.pathname = null;
		result.path = null;
	  } else {
		result.pathname = srcPath.join('/');
	  }

	  //to support request.http
	  if (!isNull(result.pathname) || !isNull(result.search)) {
		result.path = (result.pathname ? result.pathname : '') +
					  (result.search ? result.search : '');
	  }
	  result.auth = relative.auth || result.auth;
	  result.slashes = result.slashes || relative.slashes;
	  result.href = result.format();
	  return result;
	};

	Url.prototype.parseHost = function() {
	  var host = this.host;
	  var port = portPattern.exec(host);
	  if (port) {
		port = port[0];
		if (port !== ':') {
		  this.port = port.substr(1);
		}
		host = host.substr(0, host.length - port.length);
	  }
	  if (host) this.hostname = host;
	};

	var variableRegex = '(?!(?:do|if|in|for|let|new|try|var|case|else|enum|eval|false|null|this|true|void|with|break|catch|class|const|super|throw|while|yield|delete|export|import|public|return|static|switch|typeof|default|extends|finally|package|private|continue|debugger|function|arguments|interface|protected|implements|instanceof)$)[$A-Z\_a-z\xaa\xb5\xba\xc0-\xd6\xd8-\xf6\xf8-\u02c1\u02c6-\u02d1\u02e0-\u02e4\u02ec\u02ee\u0370-\u0374\u0376\u0377\u037a-\u037d\u0386\u0388-\u038a\u038c\u038e-\u03a1\u03a3-\u03f5\u03f7-\u0481\u048a-\u0527\u0531-\u0556\u0559\u0561-\u0587\u05d0-\u05ea\u05f0-\u05f2\u0620-\u064a\u066e\u066f\u0671-\u06d3\u06d5\u06e5\u06e6\u06ee\u06ef\u06fa-\u06fc\u06ff\u0710\u0712-\u072f\u074d-\u07a5\u07b1\u07ca-\u07ea\u07f4\u07f5\u07fa\u0800-\u0815\u081a\u0824\u0828\u0840-\u0858\u08a0\u08a2-\u08ac\u0904-\u0939\u093d\u0950\u0958-\u0961\u0971-\u0977\u0979-\u097f\u0985-\u098c\u098f\u0990\u0993-\u09a8\u09aa-\u09b0\u09b2\u09b6-\u09b9\u09bd\u09ce\u09dc\u09dd\u09df-\u09e1\u09f0\u09f1\u0a05-\u0a0a\u0a0f\u0a10\u0a13-\u0a28\u0a2a-\u0a30\u0a32\u0a33\u0a35\u0a36\u0a38\u0a39\u0a59-\u0a5c\u0a5e\u0a72-\u0a74\u0a85-\u0a8d\u0a8f-\u0a91\u0a93-\u0aa8\u0aaa-\u0ab0\u0ab2\u0ab3\u0ab5-\u0ab9\u0abd\u0ad0\u0ae0\u0ae1\u0b05-\u0b0c\u0b0f\u0b10\u0b13-\u0b28\u0b2a-\u0b30\u0b32\u0b33\u0b35-\u0b39\u0b3d\u0b5c\u0b5d\u0b5f-\u0b61\u0b71\u0b83\u0b85-\u0b8a\u0b8e-\u0b90\u0b92-\u0b95\u0b99\u0b9a\u0b9c\u0b9e\u0b9f\u0ba3\u0ba4\u0ba8-\u0baa\u0bae-\u0bb9\u0bd0\u0c05-\u0c0c\u0c0e-\u0c10\u0c12-\u0c28\u0c2a-\u0c33\u0c35-\u0c39\u0c3d\u0c58\u0c59\u0c60\u0c61\u0c85-\u0c8c\u0c8e-\u0c90\u0c92-\u0ca8\u0caa-\u0cb3\u0cb5-\u0cb9\u0cbd\u0cde\u0ce0\u0ce1\u0cf1\u0cf2\u0d05-\u0d0c\u0d0e-\u0d10\u0d12-\u0d3a\u0d3d\u0d4e\u0d60\u0d61\u0d7a-\u0d7f\u0d85-\u0d96\u0d9a-\u0db1\u0db3-\u0dbb\u0dbd\u0dc0-\u0dc6\u0e01-\u0e30\u0e32\u0e33\u0e40-\u0e46\u0e81\u0e82\u0e84\u0e87\u0e88\u0e8a\u0e8d\u0e94-\u0e97\u0e99-\u0e9f\u0ea1-\u0ea3\u0ea5\u0ea7\u0eaa\u0eab\u0ead-\u0eb0\u0eb2\u0eb3\u0ebd\u0ec0-\u0ec4\u0ec6\u0edc-\u0edf\u0f00\u0f40-\u0f47\u0f49-\u0f6c\u0f88-\u0f8c\u1000-\u102a\u103f\u1050-\u1055\u105a-\u105d\u1061\u1065\u1066\u106e-\u1070\u1075-\u1081\u108e\u10a0-\u10c5\u10c7\u10cd\u10d0-\u10fa\u10fc-\u1248\u124a-\u124d\u1250-\u1256\u1258\u125a-\u125d\u1260-\u1288\u128a-\u128d\u1290-\u12b0\u12b2-\u12b5\u12b8-\u12be\u12c0\u12c2-\u12c5\u12c8-\u12d6\u12d8-\u1310\u1312-\u1315\u1318-\u135a\u1380-\u138f\u13a0-\u13f4\u1401-\u166c\u166f-\u167f\u1681-\u169a\u16a0-\u16ea\u16ee-\u16f0\u1700-\u170c\u170e-\u1711\u1720-\u1731\u1740-\u1751\u1760-\u176c\u176e-\u1770\u1780-\u17b3\u17d7\u17dc\u1820-\u1877\u1880-\u18a8\u18aa\u18b0-\u18f5\u1900-\u191c\u1950-\u196d\u1970-\u1974\u1980-\u19ab\u19c1-\u19c7\u1a00-\u1a16\u1a20-\u1a54\u1aa7\u1b05-\u1b33\u1b45-\u1b4b\u1b83-\u1ba0\u1bae\u1baf\u1bba-\u1be5\u1c00-\u1c23\u1c4d-\u1c4f\u1c5a-\u1c7d\u1ce9-\u1cec\u1cee-\u1cf1\u1cf5\u1cf6\u1d00-\u1dbf\u1e00-\u1f15\u1f18-\u1f1d\u1f20-\u1f45\u1f48-\u1f4d\u1f50-\u1f57\u1f59\u1f5b\u1f5d\u1f5f-\u1f7d\u1f80-\u1fb4\u1fb6-\u1fbc\u1fbe\u1fc2-\u1fc4\u1fc6-\u1fcc\u1fd0-\u1fd3\u1fd6-\u1fdb\u1fe0-\u1fec\u1ff2-\u1ff4\u1ff6-\u1ffc\u2071\u207f\u2090-\u209c\u2102\u2107\u210a-\u2113\u2115\u2119-\u211d\u2124\u2126\u2128\u212a-\u212d\u212f-\u2139\u213c-\u213f\u2145-\u2149\u214e\u2160-\u2188\u2c00-\u2c2e\u2c30-\u2c5e\u2c60-\u2ce4\u2ceb-\u2cee\u2cf2\u2cf3\u2d00-\u2d25\u2d27\u2d2d\u2d30-\u2d67\u2d6f\u2d80-\u2d96\u2da0-\u2da6\u2da8-\u2dae\u2db0-\u2db6\u2db8-\u2dbe\u2dc0-\u2dc6\u2dc8-\u2dce\u2dd0-\u2dd6\u2dd8-\u2dde\u2e2f\u3005-\u3007\u3021-\u3029\u3031-\u3035\u3038-\u303c\u3041-\u3096\u309d-\u309f\u30a1-\u30fa\u30fc-\u30ff\u3105-\u312d\u3131-\u318e\u31a0-\u31ba\u31f0-\u31ff\u3400-\u4db5\u4e00-\u9fcc\ua000-\ua48c\ua4d0-\ua4fd\ua500-\ua60c\ua610-\ua61f\ua62a\ua62b\ua640-\ua66e\ua67f-\ua697\ua6a0-\ua6ef\ua717-\ua71f\ua722-\ua788\ua78b-\ua78e\ua790-\ua793\ua7a0-\ua7aa\ua7f8-\ua801\ua803-\ua805\ua807-\ua80a\ua80c-\ua822\ua840-\ua873\ua882-\ua8b3\ua8f2-\ua8f7\ua8fb\ua90a-\ua925\ua930-\ua946\ua960-\ua97c\ua984-\ua9b2\ua9cf\uaa00-\uaa28\uaa40-\uaa42\uaa44-\uaa4b\uaa60-\uaa76\uaa7a\uaa80-\uaaaf\uaab1\uaab5\uaab6\uaab9-\uaabd\uaac0\uaac2\uaadb-\uaadd\uaae0-\uaaea\uaaf2-\uaaf4\uab01-\uab06\uab09-\uab0e\uab11-\uab16\uab20-\uab26\uab28-\uab2e\uabc0-\uabe2\uac00-\ud7a3\ud7b0-\ud7c6\ud7cb-\ud7fb\uf900-\ufa6d\ufa70-\ufad9\ufb00-\ufb06\ufb13-\ufb17\ufb1d\ufb1f-\ufb28\ufb2a-\ufb36\ufb38-\ufb3c\ufb3e\ufb40\ufb41\ufb43\ufb44\ufb46-\ufbb1\ufbd3-\ufd3d\ufd50-\ufd8f\ufd92-\ufdc7\ufdf0-\ufdfb\ufe70-\ufe74\ufe76-\ufefc\uff21-\uff3a\uff41-\uff5a\uff66-\uffbe\uffc2-\uffc7\uffca-\uffcf\uffd2-\uffd7\uffda-\uffdc][$A-Z\_a-z\xaa\xb5\xba\xc0-\xd6\xd8-\xf6\xf8-\u02c1\u02c6-\u02d1\u02e0-\u02e4\u02ec\u02ee\u0370-\u0374\u0376\u0377\u037a-\u037d\u0386\u0388-\u038a\u038c\u038e-\u03a1\u03a3-\u03f5\u03f7-\u0481\u048a-\u0527\u0531-\u0556\u0559\u0561-\u0587\u05d0-\u05ea\u05f0-\u05f2\u0620-\u064a\u066e\u066f\u0671-\u06d3\u06d5\u06e5\u06e6\u06ee\u06ef\u06fa-\u06fc\u06ff\u0710\u0712-\u072f\u074d-\u07a5\u07b1\u07ca-\u07ea\u07f4\u07f5\u07fa\u0800-\u0815\u081a\u0824\u0828\u0840-\u0858\u08a0\u08a2-\u08ac\u0904-\u0939\u093d\u0950\u0958-\u0961\u0971-\u0977\u0979-\u097f\u0985-\u098c\u098f\u0990\u0993-\u09a8\u09aa-\u09b0\u09b2\u09b6-\u09b9\u09bd\u09ce\u09dc\u09dd\u09df-\u09e1\u09f0\u09f1\u0a05-\u0a0a\u0a0f\u0a10\u0a13-\u0a28\u0a2a-\u0a30\u0a32\u0a33\u0a35\u0a36\u0a38\u0a39\u0a59-\u0a5c\u0a5e\u0a72-\u0a74\u0a85-\u0a8d\u0a8f-\u0a91\u0a93-\u0aa8\u0aaa-\u0ab0\u0ab2\u0ab3\u0ab5-\u0ab9\u0abd\u0ad0\u0ae0\u0ae1\u0b05-\u0b0c\u0b0f\u0b10\u0b13-\u0b28\u0b2a-\u0b30\u0b32\u0b33\u0b35-\u0b39\u0b3d\u0b5c\u0b5d\u0b5f-\u0b61\u0b71\u0b83\u0b85-\u0b8a\u0b8e-\u0b90\u0b92-\u0b95\u0b99\u0b9a\u0b9c\u0b9e\u0b9f\u0ba3\u0ba4\u0ba8-\u0baa\u0bae-\u0bb9\u0bd0\u0c05-\u0c0c\u0c0e-\u0c10\u0c12-\u0c28\u0c2a-\u0c33\u0c35-\u0c39\u0c3d\u0c58\u0c59\u0c60\u0c61\u0c85-\u0c8c\u0c8e-\u0c90\u0c92-\u0ca8\u0caa-\u0cb3\u0cb5-\u0cb9\u0cbd\u0cde\u0ce0\u0ce1\u0cf1\u0cf2\u0d05-\u0d0c\u0d0e-\u0d10\u0d12-\u0d3a\u0d3d\u0d4e\u0d60\u0d61\u0d7a-\u0d7f\u0d85-\u0d96\u0d9a-\u0db1\u0db3-\u0dbb\u0dbd\u0dc0-\u0dc6\u0e01-\u0e30\u0e32\u0e33\u0e40-\u0e46\u0e81\u0e82\u0e84\u0e87\u0e88\u0e8a\u0e8d\u0e94-\u0e97\u0e99-\u0e9f\u0ea1-\u0ea3\u0ea5\u0ea7\u0eaa\u0eab\u0ead-\u0eb0\u0eb2\u0eb3\u0ebd\u0ec0-\u0ec4\u0ec6\u0edc-\u0edf\u0f00\u0f40-\u0f47\u0f49-\u0f6c\u0f88-\u0f8c\u1000-\u102a\u103f\u1050-\u1055\u105a-\u105d\u1061\u1065\u1066\u106e-\u1070\u1075-\u1081\u108e\u10a0-\u10c5\u10c7\u10cd\u10d0-\u10fa\u10fc-\u1248\u124a-\u124d\u1250-\u1256\u1258\u125a-\u125d\u1260-\u1288\u128a-\u128d\u1290-\u12b0\u12b2-\u12b5\u12b8-\u12be\u12c0\u12c2-\u12c5\u12c8-\u12d6\u12d8-\u1310\u1312-\u1315\u1318-\u135a\u1380-\u138f\u13a0-\u13f4\u1401-\u166c\u166f-\u167f\u1681-\u169a\u16a0-\u16ea\u16ee-\u16f0\u1700-\u170c\u170e-\u1711\u1720-\u1731\u1740-\u1751\u1760-\u176c\u176e-\u1770\u1780-\u17b3\u17d7\u17dc\u1820-\u1877\u1880-\u18a8\u18aa\u18b0-\u18f5\u1900-\u191c\u1950-\u196d\u1970-\u1974\u1980-\u19ab\u19c1-\u19c7\u1a00-\u1a16\u1a20-\u1a54\u1aa7\u1b05-\u1b33\u1b45-\u1b4b\u1b83-\u1ba0\u1bae\u1baf\u1bba-\u1be5\u1c00-\u1c23\u1c4d-\u1c4f\u1c5a-\u1c7d\u1ce9-\u1cec\u1cee-\u1cf1\u1cf5\u1cf6\u1d00-\u1dbf\u1e00-\u1f15\u1f18-\u1f1d\u1f20-\u1f45\u1f48-\u1f4d\u1f50-\u1f57\u1f59\u1f5b\u1f5d\u1f5f-\u1f7d\u1f80-\u1fb4\u1fb6-\u1fbc\u1fbe\u1fc2-\u1fc4\u1fc6-\u1fcc\u1fd0-\u1fd3\u1fd6-\u1fdb\u1fe0-\u1fec\u1ff2-\u1ff4\u1ff6-\u1ffc\u2071\u207f\u2090-\u209c\u2102\u2107\u210a-\u2113\u2115\u2119-\u211d\u2124\u2126\u2128\u212a-\u212d\u212f-\u2139\u213c-\u213f\u2145-\u2149\u214e\u2160-\u2188\u2c00-\u2c2e\u2c30-\u2c5e\u2c60-\u2ce4\u2ceb-\u2cee\u2cf2\u2cf3\u2d00-\u2d25\u2d27\u2d2d\u2d30-\u2d67\u2d6f\u2d80-\u2d96\u2da0-\u2da6\u2da8-\u2dae\u2db0-\u2db6\u2db8-\u2dbe\u2dc0-\u2dc6\u2dc8-\u2dce\u2dd0-\u2dd6\u2dd8-\u2dde\u2e2f\u3005-\u3007\u3021-\u3029\u3031-\u3035\u3038-\u303c\u3041-\u3096\u309d-\u309f\u30a1-\u30fa\u30fc-\u30ff\u3105-\u312d\u3131-\u318e\u31a0-\u31ba\u31f0-\u31ff\u3400-\u4db5\u4e00-\u9fcc\ua000-\ua48c\ua4d0-\ua4fd\ua500-\ua60c\ua610-\ua61f\ua62a\ua62b\ua640-\ua66e\ua67f-\ua697\ua6a0-\ua6ef\ua717-\ua71f\ua722-\ua788\ua78b-\ua78e\ua790-\ua793\ua7a0-\ua7aa\ua7f8-\ua801\ua803-\ua805\ua807-\ua80a\ua80c-\ua822\ua840-\ua873\ua882-\ua8b3\ua8f2-\ua8f7\ua8fb\ua90a-\ua925\ua930-\ua946\ua960-\ua97c\ua984-\ua9b2\ua9cf\uaa00-\uaa28\uaa40-\uaa42\uaa44-\uaa4b\uaa60-\uaa76\uaa7a\uaa80-\uaaaf\uaab1\uaab5\uaab6\uaab9-\uaabd\uaac0\uaac2\uaadb-\uaadd\uaae0-\uaaea\uaaf2-\uaaf4\uab01-\uab06\uab09-\uab0e\uab11-\uab16\uab20-\uab26\uab28-\uab2e\uabc0-\uabe2\uac00-\ud7a3\ud7b0-\ud7c6\ud7cb-\ud7fb\uf900-\ufa6d\ufa70-\ufad9\ufb00-\ufb06\ufb13-\ufb17\ufb1d\ufb1f-\ufb28\ufb2a-\ufb36\ufb38-\ufb3c\ufb3e\ufb40\ufb41\ufb43\ufb44\ufb46-\ufbb1\ufbd3-\ufd3d\ufd50-\ufd8f\ufd92-\ufdc7\ufdf0-\ufdfb\ufe70-\ufe74\ufe76-\ufefc\uff21-\uff3a\uff41-\uff5a\uff66-\uffbe\uffc2-\uffc7\uffca-\uffcf\uffd2-\uffd7\uffda-\uffdc0-9\u0300-\u036f\u0483-\u0487\u0591-\u05bd\u05bf\u05c1\u05c2\u05c4\u05c5\u05c7\u0610-\u061a\u064b-\u0669\u0670\u06d6-\u06dc\u06df-\u06e4\u06e7\u06e8\u06ea-\u06ed\u06f0-\u06f9\u0711\u0730-\u074a\u07a6-\u07b0\u07c0-\u07c9\u07eb-\u07f3\u0816-\u0819\u081b-\u0823\u0825-\u0827\u0829-\u082d\u0859-\u085b\u08e4-\u08fe\u0900-\u0903\u093a-\u093c\u093e-\u094f\u0951-\u0957\u0962\u0963\u0966-\u096f\u0981-\u0983\u09bc\u09be-\u09c4\u09c7\u09c8\u09cb-\u09cd\u09d7\u09e2\u09e3\u09e6-\u09ef\u0a01-\u0a03\u0a3c\u0a3e-\u0a42\u0a47\u0a48\u0a4b-\u0a4d\u0a51\u0a66-\u0a71\u0a75\u0a81-\u0a83\u0abc\u0abe-\u0ac5\u0ac7-\u0ac9\u0acb-\u0acd\u0ae2\u0ae3\u0ae6-\u0aef\u0b01-\u0b03\u0b3c\u0b3e-\u0b44\u0b47\u0b48\u0b4b-\u0b4d\u0b56\u0b57\u0b62\u0b63\u0b66-\u0b6f\u0b82\u0bbe-\u0bc2\u0bc6-\u0bc8\u0bca-\u0bcd\u0bd7\u0be6-\u0bef\u0c01-\u0c03\u0c3e-\u0c44\u0c46-\u0c48\u0c4a-\u0c4d\u0c55\u0c56\u0c62\u0c63\u0c66-\u0c6f\u0c82\u0c83\u0cbc\u0cbe-\u0cc4\u0cc6-\u0cc8\u0cca-\u0ccd\u0cd5\u0cd6\u0ce2\u0ce3\u0ce6-\u0cef\u0d02\u0d03\u0d3e-\u0d44\u0d46-\u0d48\u0d4a-\u0d4d\u0d57\u0d62\u0d63\u0d66-\u0d6f\u0d82\u0d83\u0dca\u0dcf-\u0dd4\u0dd6\u0dd8-\u0ddf\u0df2\u0df3\u0e31\u0e34-\u0e3a\u0e47-\u0e4e\u0e50-\u0e59\u0eb1\u0eb4-\u0eb9\u0ebb\u0ebc\u0ec8-\u0ecd\u0ed0-\u0ed9\u0f18\u0f19\u0f20-\u0f29\u0f35\u0f37\u0f39\u0f3e\u0f3f\u0f71-\u0f84\u0f86\u0f87\u0f8d-\u0f97\u0f99-\u0fbc\u0fc6\u102b-\u103e\u1040-\u1049\u1056-\u1059\u105e-\u1060\u1062-\u1064\u1067-\u106d\u1071-\u1074\u1082-\u108d\u108f-\u109d\u135d-\u135f\u1712-\u1714\u1732-\u1734\u1752\u1753\u1772\u1773\u17b4-\u17d3\u17dd\u17e0-\u17e9\u180b-\u180d\u1810-\u1819\u18a9\u1920-\u192b\u1930-\u193b\u1946-\u194f\u19b0-\u19c0\u19c8\u19c9\u19d0-\u19d9\u1a17-\u1a1b\u1a55-\u1a5e\u1a60-\u1a7c\u1a7f-\u1a89\u1a90-\u1a99\u1b00-\u1b04\u1b34-\u1b44\u1b50-\u1b59\u1b6b-\u1b73\u1b80-\u1b82\u1ba1-\u1bad\u1bb0-\u1bb9\u1be6-\u1bf3\u1c24-\u1c37\u1c40-\u1c49\u1c50-\u1c59\u1cd0-\u1cd2\u1cd4-\u1ce8\u1ced\u1cf2-\u1cf4\u1dc0-\u1de6\u1dfc-\u1dff\u200c\u200d\u203f\u2040\u2054\u20d0-\u20dc\u20e1\u20e5-\u20f0\u2cef-\u2cf1\u2d7f\u2de0-\u2dff\u302a-\u302f\u3099\u309a\ua620-\ua629\ua66f\ua674-\ua67d\ua69f\ua6f0\ua6f1\ua802\ua806\ua80b\ua823-\ua827\ua880\ua881\ua8b4-\ua8c4\ua8d0-\ua8d9\ua8e0-\ua8f1\ua900-\ua909\ua926-\ua92d\ua947-\ua953\ua980-\ua983\ua9b3-\ua9c0\ua9d0-\ua9d9\uaa29-\uaa36\uaa43\uaa4c\uaa4d\uaa50-\uaa59\uaa7b\uaab0\uaab2-\uaab4\uaab7\uaab8\uaabe\uaabf\uaac1\uaaeb-\uaaef\uaaf5\uaaf6\uabe3-\uabea\uabec\uabed\uabf0-\uabf9\ufb1e\ufe00-\ufe0f\ufe20-\ufe26\ufe33\ufe34\ufe4d-\ufe4f\uff10-\uff19\uff3f]*';
	var partRegex = new RegExp('{(' + variableRegex + ')}', 'gi');

	function StaticUrlPart(part) {
		this.part = part;
	}

	StaticUrlPart.prototype.reset = function () {
	};

	StaticUrlPart.prototype.getRegex = function () {
		return this.part;
	};

	StaticUrlPart.prototype.format = function (params, found) {
		return this.part;
	};

	function PlaceholderUrlPart(part, position) {
		this.part = part;
		this.position = position;
	}

	PlaceholderUrlPart.prototype.reset = function () {
		this.hasAppeared = false;
	};

	PlaceholderUrlPart.prototype.getRegex = function () {
		if (this.hasAppeared) {
			return '\\' + this.position;
		} else {
			this.hasAppeared = true;
			return '(.*?)'
		}
	};

	PlaceholderUrlPart.prototype.format = function (params, found) {
		found[this.part] = true;
		var value = params[this.part];
		value = encodeURIComponent(value);
		return value;
	};

	function UrlPartCollection() {
		this.parts = [];
		this.count = 1;
		this.placeholders = {};
		this.indexes = {};
	}

	UrlPartCollection.prototype.createStatic = function (part) {
		return new StaticUrlPart(part);
	};

	UrlPartCollection.prototype.createPlaceholder = function (part) {
		if (part in this.placeholders) {
			return placeholders[part];
		} else {
			var placeholder = new PlaceholderUrlPart(part, this.count);
			this.placeholders[part] = placeholder;
			this.indexes[this.count] = placeholder;
			++this.count;
			return placeholder;
		}
	};

	UrlPartCollection.prototype.add = function (part) {
		this.parts.push(part);
	};

	UrlPartCollection.prototype.reset = function () {
		for (var index = 0; index !== this.parts.length; ++index) {
			var part = this.parts[index];
			parts.reset();
		}
	};

	UrlPartCollection.prototype.getRegex = function () {
		var regexParts = ['^'];
		for (var index = 0; index !== this.parts.length; ++index) {
			var part = this.parts[index];
			regexParts.push(part.getRegex());
		}
		regexParts.push('$');
		var regex = regexParts.join('');
		return regex;
	};

	UrlPartCollection.prototype.extract = function (match, params) {
		for (var index = 1; index !== match.length; ++index) {
			var name = this.indexes[index].part;
			params[name] = decodeURIComponent(match[index]);
		}
	};

	UrlPartCollection.prototype.format = function (params, found) {
		var parts = [];
		for (var index = 0; index !== this.parts.length; ++index) {
			var part = this.parts[index];
			parts.push(part.format(params, found));
		}
		var url = parts.join('');
		return url;
	};

	function UrlTemplate(collection) {
		this.collection = collection;
	}

	UrlTemplate.prototype.extract = function (path) {
		var url = new Url();
		var parts = url.parse(path, true);
		var prefix = getPrefix(parts);
		
		this.regex = this.regex || new RegExp(this.collection.getRegex());
		var match = this.regex.exec(prefix);
		if (isNull(match)) {
			throw new Error('The path did not match the template.');
		}
		
		var params = {};
		for (var queryKey in parts.query) {
			params[queryKey] = parts.query[queryKey];
		}
		this.collection.extract(match, params);
		return params;
	};

	UrlTemplate.prototype.format = function (params) {
		var found = {};
		var url = this.collection.format(params, found);
		
		var pairs = [];
		for (var param in params) {
			if (!(param in found)) {
				var key = encodeURIComponent(param);
				var value = encodeURIComponent(params[param]);
				pairs.push(key + '=' + value);
			}
		}
		if (pairs.length !== 0) {
			url += '?' + pairs.join('&');
		}
		
		return url;
	};

	function getPrefix(parts) {
		var builder = [];
		builder.push(parts.protocol, '//');
		if (parts.auth){
			builder.push(parts.auth);
		}
		builder.push(parts.host);
		builder.push(parts.pathname);
		var prefix = builder.join('');
		return prefix;
	}

	function getPartCollection(parts) {
		var collection = new UrlPartCollection();
		var lastIndex = 0;	
		var path = getPrefix(parts);
		var match = partRegex.exec(path);
		while (!isNull(match)) {
			var prefix = path.substring(lastIndex, match.index);
			var prefixPart = collection.createStatic(prefix);
			collection.add(prefixPart);
			
			var capture = match[1];
			var placeholder = collection.createPlaceholder(capture);
			collection.add(placeholder);
			
			lastIndex = match.index + capture.length + 2;
			match = partRegex.exec(path);
		}
		
		var postfix = path.substring(lastIndex);
		var postfixPart = collection.createStatic(postfix);
		collection.add(postfixPart);
		
		return collection;
	}

	return function (template) {
		var url = new Url();
		var parts = url.parse(template, false);
		var collection = getPartCollection(parts);
		return new UrlTemplate(collection);
	};
})();