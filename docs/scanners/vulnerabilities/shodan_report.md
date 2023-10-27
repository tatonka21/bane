<body>
<main>
<article id="content">
<header>
<h1 class="title">Module <code>bane.scanners.vulnerabilities.shodan_report</code></h1>
</header>
<section id="section-intro">
<details class="source">
<summary>
<span>Expand source code</span>
</summary>
<pre><code class="python">from bane.scanners.vulnerabilities.utils import *


def shodan_report(ip, api_key, file_name=&#34;shodan_report&#34;,save_to_file=False,proxy=None):
    u = &#34;https://api.shodan.io/shodan/host/{}?key={}&#34;.format(ip, api_key)
    try:
        r = requests.Session().get(u, headers={&#34;User-Agent&#34;: random.choice(ua)},proxies=proxy).text
        if save_to_file==True:
            with open(file_name.split(&#34;.&#34;)[0] + &#34;.json&#34;, &#34;w&#34;) as outfile:
                json.dump(json.loads(r), outfile, indent=4)
            outfile.close()
        return json.loads(r)
    except:
        return {}</code></pre>
</details>
</section>
<section>
</section>
<section>
</section>
<section>
<h2 class="section-title" id="header-functions">Functions</h2>
<dl>
<dt id="bane.scanners.vulnerabilities.shodan_report.shodan_report"><code class="name flex">
<span>def <span class="ident">shodan_report</span></span>(<span>ip, api_key, file_name='shodan_report', save_to_file=False, proxy=None)</span>
</code></dt>
<dd>
<div class="desc"></div>
<details class="source">
<summary>
<span>Expand source code</span>
</summary>
<pre><code class="python">def shodan_report(ip, api_key, file_name=&#34;shodan_report&#34;,save_to_file=False,proxy=None):
    u = &#34;https://api.shodan.io/shodan/host/{}?key={}&#34;.format(ip, api_key)
    try:
        r = requests.Session().get(u, headers={&#34;User-Agent&#34;: random.choice(ua)},proxies=proxy).text
        if save_to_file==True:
            with open(file_name.split(&#34;.&#34;)[0] + &#34;.json&#34;, &#34;w&#34;) as outfile:
                json.dump(json.loads(r), outfile, indent=4)
            outfile.close()
        return json.loads(r)
    except:
        return {}</code></pre>
</details>
</dd>
</dl>
</section>
<section>
</section>
</article>
<nav id="sidebar">
<h1>Index</h1>
<div class="toc">
<ul></ul>
</div>
<ul id="index">
<li><h3>Super-module</h3>
<ul>
<li><code><a title="bane.scanners.vulnerabilities" href="index.md">bane.scanners.vulnerabilities</a></code></li>
</ul>
</li>
<li><h3><a href="#header-functions">Functions</a></h3>
<ul class="">
<li><code><a title="bane.scanners.vulnerabilities.shodan_report.shodan_report" href="#bane.scanners.vulnerabilities.shodan_report.shodan_report">shodan_report</a></code></li>
</ul>
</li>
</ul>
</nav>
</main>
<footer id="footer">
<p>Generated by <a href="https://pdoc3.github.io/pdoc" title="pdoc: Python API documentation generator"><cite>pdoc</cite> 0.10.0</a>.</p>
</footer>
</body>
</html>