<body>
<main>
<article id="content">
<header>
<h1 class="title">Module <code>bane.scanners.vulnerabilities.springboot_actuator</code></h1>
</header>
<section id="section-intro">
<details class="source">
<summary>
<span>Expand source code</span>
</summary>
<pre><code class="python">from bane.scanners.vulnerabilities.utils import *

def springboot_actuator(u,user_agent=None,cookie=None,proxy=None,timeout=None,path=&#39;/actuator&#39;,headers={}):
    if u[len(u) - 1] == &#34;/&#34;:
        u = u[0 : len(u) - 1]
    if user_agent:
        us = user_agent
    else:
        us = random.choice(ua)
    hed = {&#34;User-Agent&#34;: us}
    if cookie:
        hed.update({&#34;Cookie&#34;: cookie})
    hed.update(headers)
    try:
        return requests.Session().get(
            u + path,
            headers=hed,
            proxies=proxy,
            timeout=timeout,
            verify=False,
        ).json()
    except:
        pass</code></pre>
</details>
</section>
<section>
</section>
<section>
</section>
<section>
<h2 class="section-title" id="header-functions">Functions</h2>
<dl>
<dt id="bane.scanners.vulnerabilities.springboot_actuator.springboot_actuator"><code class="name flex">
<span>def <span class="ident">springboot_actuator</span></span>(<span>u, user_agent=None, cookie=None, proxy=None, timeout=None, path='/actuator', headers={})</span>
</code></dt>
<dd>
<div class="desc"></div>
<details class="source">
<summary>
<span>Expand source code</span>
</summary>
<pre><code class="python">def springboot_actuator(u,user_agent=None,cookie=None,proxy=None,timeout=None,path=&#39;/actuator&#39;,headers={}):
    if u[len(u) - 1] == &#34;/&#34;:
        u = u[0 : len(u) - 1]
    if user_agent:
        us = user_agent
    else:
        us = random.choice(ua)
    hed = {&#34;User-Agent&#34;: us}
    if cookie:
        hed.update({&#34;Cookie&#34;: cookie})
    hed.update(headers)
    try:
        return requests.Session().get(
            u + path,
            headers=hed,
            proxies=proxy,
            timeout=timeout,
            verify=False,
        ).json()
    except:
        pass</code></pre>
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
<li><code><a title="bane.scanners.vulnerabilities.springboot_actuator.springboot_actuator" href="#bane.scanners.vulnerabilities.springboot_actuator.springboot_actuator">springboot_actuator</a></code></li>
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