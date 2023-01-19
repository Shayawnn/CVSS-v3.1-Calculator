var CVSS = function(id, options) {
    this.options = options;
    this.wId = id;
    var e = function(tag) {
        return document.createElement(tag);
    };

    // Base Group
    this.bg = {
        AV: 'Attack Vector',
        AC: 'Attack Complexity',
        PR: 'Privileges Required',
        UI: 'User Interaction',
    };

    // Base Metrics
    this.bm = {
        AV: {
            N: {
                l: 'Network',
                d: "<b>Worst:</b> The vulnerable component is bound to the network stack and the set of possible attackers extends beyond the other options listed below, up to and including the entire Internet. Such a vulnerability is often termed “remotely exploitable” and can be thought of as an attack being exploitable at the protocol level one or more network hops away (e.g., across one or more routers)."
            },
            A: {
                l: 'Adjacent',
                d: "<b>Worse:</b> The vulnerable component is bound to the network stack, but the attack is limited at the protocol level to a logically adjacent topology. This can mean an attack must be launched from the same shared physical (e.g., Bluetooth or IEEE 802.11) or logical (e.g., local IP subnet) network, or from within a secure or otherwise limited administrative domain (e.g., MPLS, secure VPN to an administrative network zone). One example of an Adjacent attack would be an ARP (IPv4) or neighbor discovery (IPv6) flood leading to a denial of service on the local LAN segment."
            },
            L: {
                l: 'Local',
                d: "<b>Bad:</b> The vulnerable component is not bound to the network stack and the attacker’s path is via read/write/execute capabilities. Either: <ul><li>the attacker exploits the vulnerability by accessing the target system locally (e.g., keyboard, console), or remotely (e.g., SSH);</li><li>or the attacker relies on User Interaction by another person to perform actions required to exploit the vulnerability (e.g., using social engineering techniques to trick a legitimate user into opening a malicious document).</li></ul>"
            },
            P: {
                l: 'Physical',
                d: "<b>Bad:</b> The attack requires the attacker to physically touch or manipulate the vulnerable component. Physical interaction may be brief (e.g., evil maid attack) or persistent. An example of such an attack is a cold boot attack in which an attacker gains access to disk encryption keys after physically accessing the target system. Other examples include peripheral attacks via FireWire/USB Direct Memory Access (DMA)."
            }
        },
        AC: {
            L: {
                l: 'Low',
                d: "<b>Worst:</b> Specialized access conditions or extenuating circumstances do not exist. An attacker can expect repeatable success when attacking the vulnerable component."
            },
            H: {
                l: 'High',
                d: "<b>Bad:</b> A successful attack depends on conditions beyond the attacker's control. That is, a successful attack cannot be accomplished at will, but requires the attacker to invest in some measurable amount of effort in preparation or execution against the vulnerable component before a successful attack can be expected."
            }
        },
        PR: {
            N: {
                l: 'None',
                d: "<b>Worst:</b> The attacker is unauthorized prior to attack, and therefore does not require any access to settings or files of the the vulnerable system to carry out an attack."
            },
            L: {
                l: 'Low',
                d: "<b>Worse</b> The attacker requires privileges that provide basic user capabilities that could normally affect only settings and files owned by a user. Alternatively, an attacker with Low privileges has the ability to access only non-sensitive resources."
            },
            H: {
                l: 'High',
                d: "<b>Bad:</b> The attacker requires privileges that provide significant (e.g., administrative) control over the vulnerable component allowing access to component-wide settings and files."
            }
        },
        UI: {
            N: {
                l: 'None',
                d: "<b>Worst:</b> The vulnerable system can be exploited without interaction from any user."
            },
            R: {
                l: 'Required',
                d: "<b>Bad:</b> Successful exploitation of this vulnerability requires a user to take some action before the vulnerability can be exploited. For example, a successful exploit may only be possible during the installation of an application by a system administrator."
            }
        }
    };

    this.bme = {};
    this.bmgReg = {
        AV: 'NALP',
        AC: 'LH',
        PR: 'NLH',
        UI: 'NR',
    };
    this.bmoReg = {
        AV: 'NALP',
        AC: 'LH',
    };
    var s, f, dl, g, dd, l;
    this.el = document.getElementById(id);
    this.el.appendChild(s = e('style'));
    s.innerHTML = '';
    this.el.appendChild(f = e('form'));
    f.className = 'cvssjs';
    this.calc = f;
    for (g in this.bg) {
        f.appendChild(dl = e('dl'));
        dl.setAttribute('class', g);
        var dt = e('dt');
        dt.innerHTML = this.bg[g];
        dl.appendChild(dt);
        for (s in this.bm[g]) {
            dd = e('dd');
            dl.appendChild(dd);
            var inp = e('input');
            inp.setAttribute('name', g);
            inp.setAttribute('value', s);
            inp.setAttribute('id', id + g + s);
            inp.setAttribute('class', g + s);
            //inp.setAttribute('ontouchstart', '');
            inp.setAttribute('type', 'radio');
            this.bme[g + s] = inp;
            var me = this;
            inp.onchange = function() {
                me.setMetric(this);
            }
            ;
            dd.appendChild(inp);
            l = e('label');
            dd.appendChild(l);
            l.setAttribute('for', id + g + s);
            l.appendChild(e('i')).setAttribute('class', g + s);
            l.appendChild(document.createTextNode(this.bm[g][s].l + ' '));
            dd.appendChild(e('small')).innerHTML = this.bm[g][s].d;
        }
    }
    f.appendChild(dl = e('dl'));
    dl.innerHTML = '<dt>Severity&sdot;Score&sdot;Vector</dt>';
    dd = e('dd');
    dl.appendChild(dd);
    l = dd.appendChild(e('label'));
    l.className = 'results';
    l.appendChild(this.severity = e('span'));
    this.severity.className = 'severity';
    l.appendChild(this.score = e('span'));
    this.score.className = 'score';
    l.appendChild(document.createTextNode(' '));
    l.appendChild(this.vector = e('a'));
    this.vector.className = 'vector';
    this.vector.innerHTML = 'CVSS:3.1/AV:_/AC:_/PR:_/UI:_';
    // setup the copy button/icon
    l.appendChild(document.createTextNode(' '));
    l.appendChild(this.copyButton = e('a'))
    this.copyButton.style.visibility = "hidden"
    this.copyButton.className = "copy-button"
    this.copyButton.title = "Copy Vector to Clipboard"
    this.copyButton.innerHTML = 'Copy'
    this.copyButton.onclick = function() {
        navigator.clipboard.writeText(document.querySelector(".vector").innerText)
    }

    if (options.onsubmit) {
        f.appendChild(e('hr'));
        this.submitButton = f.appendChild(e('input'));
        this.submitButton.setAttribute('type', 'submit');
        this.submitButton.onclick = options.onsubmit;
    }
};

CVSS.prototype.severityRatings = [{
    name: "None",
    bottom: 0.0,
    top: 0.0
}, {
    name: "VeryLow",
    bottom: 0.1,
    top: 1.05
}, {
    name: "Low",
    bottom: 1.06,
    top: 1.99
}, {
    name: "Medium",
    bottom: 2.00,
    top: 2.95
}, {
    name: "High",
    bottom: 2.96,
    top: 3.9
}];

CVSS.prototype.severityRating = function(score) {
    var i;
    var severityRatingLength = this.severityRatings.length;
    for (i = 0; i < severityRatingLength; i++) {
        if (score >= this.severityRatings[i].bottom && score <= this.severityRatings[i].top) {
            return this.severityRatings[i];
        }
    }
    return {
        name: "?",
        bottom: 'Not',
        top: 'defined'
    };
}
;

CVSS.prototype.valueofradio = function(e) {
    for (var i = 0; i < e.length; i++) {
        if (e[i].checked) {
            return e[i].value;
        }
    }
    return null;
}
;

CVSS.prototype.calculate = function() {
    var cvssVersion = "3.1";
    var exploitabilityCoefficient = 8.22;
    var scopeCoefficient = 1.08;

    // Define associative arrays mapping each metric value to the constant used in the CVSS scoring formula.
    var Weight = {
        AV: {
            N: 0.85,
            A: 0.62,
            L: 0.55,
            P: 0.2
        },
        AC: {
            H: 0.44,
            L: 0.77
        },
        PR: {
            N: 0.85,
            L: 0.62,
            H: 0.27
        },
        UI: {
            N: 0.85,
            R: 0.62
        }
    };

    var p;
    var val = {}
      , metricWeight = {};
    try {
        for (p in this.bg) {
            val[p] = this.valueofradio(this.calc.elements[p]);
            if (typeof val[p] === "undefined" || val[p] === null) {
                return "?";
            }
            metricWeight[p] = Weight[p][val[p]];

            console.log(metricWeight)
        }
    } catch (err) {
        return err;
    }
    // CALCULATE THE CVSS BASE SCORE
    try {
        var baseScore;

        var baseScore = exploitabilityCoefficient * metricWeight.AV * metricWeight.AC * metricWeight.PR * metricWeight.UI;

        console.log(baseScore)

        return baseScore.toFixed(1);
    } catch (err) {
        return err;
    }
}
;

CVSS.prototype.get = function() {
    return {
        score: this.score.innerHTML,
        vector: this.vector.innerHTML
    };
}
;

CVSS.prototype.setMetric = function(a) {
    var vectorString = this.vector.innerHTML;
    if (/AV:.\/AC:.\/PR:.\/UI:./.test(vectorString)) {} else {
        vectorString = 'AV:_/AC:_/PR:_/UI:_';
    }
    var newVec = vectorString.replace(new RegExp('\\b' + a.name + ':.'), a.name + ':' + a.value);
    this.set(newVec);
}
;

CVSS.prototype.set = function(vec) {
    var newVec = 'CVSS:3.1/';
    var sep = '';
    for (var m in this.bm) {
        var match = (new RegExp('\\b(' + m + ':[' + this.bmgReg[m] + '])')).exec(vec);
        if (match !== null) {
            var check = match[0].replace(':', '');
            this.bme[check].checked = true;
            newVec = newVec + sep + match[0];
        } else if ((m in {
            C: '',
            I: '',
            A: ''
        }) && (match = (new RegExp('\\b(' + m + ':C)')).exec(vec)) !== null) {
            // compatibility with v2 only for CIA:C
            this.bme[m + 'H'].checked = true;
            newVec = newVec + sep + m + ':H';
        } else {
            newVec = newVec + sep + m + ':_';
            for (var j in this.bm[m]) {
                this.bme[m + j].checked = false;
            }
        }
        sep = '/';
    }
    this.update(newVec);
}
;

CVSS.prototype.update = function(newVec) {
    this.vector.innerHTML = newVec;
    var s = this.calculate();
    this.score.innerHTML = s;
    var rating = this.severityRating(s);
    this.severity.className = rating.name + ' severity';
    this.severity.innerHTML = rating.name + '<sub>' + rating.bottom + ' - ' + rating.top + '</sub>';
    this.severity.title = rating.bottom + ' - ' + rating.top;
    if (rating['name'] != '?') {
        this.copyButton.style.visibility = "visible"
    }
    if (this.options !== undefined && this.options.onchange !== undefined) {
        this.options.onchange();
    }
}
;
