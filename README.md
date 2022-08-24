# Copy and customize from Web Audit Search Engine
fix something to run :))
# Install 
1. Install ElasticSearch and Kibana on your server.
* set the following options in `/etc/elasticsearch/elasticsearch.yml` to allow connection to ElasticSearch from LAN: <br>
  `discovery.type: single-node`<br>
  `network.host: 0.0.0.0`

2. Install ElasticBurp via BurpSuite Extender.
3. Find the folder of ElasticBurp.
![image](https://user-images.githubusercontent.com/43785370/183043529-05195637-d0ea-47d1-8096-f76d6a7d4a04.png)
* Window: C:\Users\Nothing\AppData\Roaming\BurpSuite\bapps\67f5c31f93d04ad3a3b0a1808b3648fa
* Linux: /home/kali/.BurpSuite/bapps/67f5c31f93d04ad3a3b0a1808b3648fa/
4. Replace all the files inside ElasticBurp folder with those files inside this repository.  
5. Restart BurpSuite and set 'ElasticSearch Host' and 'ElasticSearch Index' inside ElasticBurp Tab.
![image](https://user-images.githubusercontent.com/43785370/183050436-d4691786-ea79-4b77-8c11-d4f60d7d4802.png)
6. Check the Output Log to confirm your connection
![image](https://user-images.githubusercontent.com/97270758/183054869-7cee7208-3e4e-4227-a63d-67e864c95478.png)
7. Enjoy
# Tested on
ElasticSearch [7.17.5](https://www.elastic.co/downloads/past-releases/elasticsearch-7-17-5)   <br>
Redis [5.0.14.1](https://github.com/tporadowski/redis/releases) <br>
Redis [3.0.504](https://github.com/microsoftarchive/redis/releases/tag/win-3.0.504) <br>
# [Change Log](CHANGELOG.md) 
# Todo 

- [x] Reduce duplicated requests with redis.
- [x] Requests Sharing.
- [x] Adding Advanced Search
- [ ] Reduce missing requests from ConnectionTimeout
