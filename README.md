AFProxy -- Another Filtering Proxy
==================================

Version 0.4 (20141221)
--------------

* List files not bundled and inited in URLFilter.py any more, now globle available to other filters
+ Unfiltered content is streamed to client, while not cached before sending
* Fix config auto reload
* Fix Privoxy parse (replace '.*' in the host regex with '[^/]*' so it won't match the path string)

Version 0.3 (20141205)
--------------

+ URLFilter.py now supports multiple list files for each filter
+ Parse Privoxy actions files (default.action, user.action) for URL blocking
* List files moved to <Lists> directory

Version 0.2 (20141129)
--------------

+ Privoxy style URL patterns for block, bypass and filters URL matching
+ Basic header filtering: HeaderFilter.py
+ Basic web page filtering: PageFilter.py
+ Config auto reload

Version 0.1 (20141122)
--------------

Initial release

+ URL blocking
+ URL redirecting
+ Filtering bypass
+ Regex support for above actions
