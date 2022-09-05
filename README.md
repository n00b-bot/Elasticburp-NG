# Installation 
1. Install ElasticSearch and Kibana on your server.
* set the following options in `/etc/elasticsearch/elasticsearch.yml` to allow connection to ElasticSearch from LAN: <br>
  `discovery.type: single-node`<br>
  `network.host: 0.0.0.0`  
  
  
2. Install Jython.

![image](https://user-images.githubusercontent.com/97270758/188395883-99c473c5-1171-4892-b7f7-37a4dacffdd3.png)

3. Install ElasticBurp via the BApp Store feature in the Burp Extender tool.

https://user-images.githubusercontent.com/97270758/188395112-90379af0-e573-4b4c-98ba-8d89ec001ff6.mp4

4. Find ElasticBurp's directory.
* Window: `%appdata%\BurpSuite\bapps\67f5c31f93d04ad3a3b0a1808b3648fa\`
* Linux: `/home/{user}/.BurpSuite/bapps/67f5c31f93d04ad3a3b0a1808b3648fa/`

5. Overwrite ElasticBurp-NG's files to the original ElasticBurp's directory. To get our files, you can clone this repository (recommend this for future updates) or download a zip file.
* Window:

https://user-images.githubusercontent.com/97270758/188400165-addb85c3-d211-4d73-9ed9-0a074522604e.mp4

* Linux:

https://user-images.githubusercontent.com/97270758/188401266-c4995912-dbbe-4624-9269-d9964d2922a8.mp4


6. Reactive ElasticBurp and set your 'ElasticSearch Host' and 'ElasticSearch Index' in the ElasticBurp Tab and then check the Output Log to confirm your connection.

https://user-images.githubusercontent.com/97270758/188400426-299f1227-2d4c-42f0-977c-78248d30bc3a.mp4

7. Enjoy!

# Features
- Requests Sharing

- Advanced Search

# Demo

https://user-images.githubusercontent.com/97270758/188403933-6de89bc1-152d-4ef9-b356-28c9f315e826.mp4

# Tested on
ElasticSearch [7.17.5](https://www.elastic.co/downloads/past-releases/elasticsearch-7-17-5)   <br>
Redis [5.0.14.1](https://github.com/tporadowski/redis/releases) <br>
Redis [3.0.504](https://github.com/microsoftarchive/redis/releases/tag/win-3.0.504) <br>
# [Change Log](CHANGELOG.md) 
# Todo 

- [x] Reduce duplicated requests with redis.
- [x] Requests Sharing.
- [X] Adding Advanced Search
- [ ] Reduce missing requests from ConnectionTimeout
