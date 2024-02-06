# Implements Amazon AWS v4 Authentication

## SYNOPSYS

```
(use app.amazon.auth)

(let* ([signing-key
         (aws4-signing-key :access-id "YOUR_AWS_ACCESS_ID"
                           :secret-key "YOUR_AWS_SECERT_KEY"
                           :service "s3"))
       [original-headers '(...your original headers...)]
       [signed-headers
         (aws4-add-auth-headers signing-key 'GET
                                "https://your-service.amazon.com/resource-path"
                                original-headers
                                #f)])
  (http-get "your-service.amazon.com" "/resource-path"
            :secure #t
            :headers signed-headers))
```

## DESCPRIPTION

This module provides basic methods to add authentication information
to access AWS API.