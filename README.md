# ECC
### (ERM Chunk Controller)
- Used for the deployment of multiple instances for ERM, allowing for seamless token information attainment, shard information, custom bot information and more.
- Used for the automatic interoperability between API functionalities across multiple instances, allowing for the easy communication between endpoints and their custom interfaces.

### Technologies Relied Upon
- *MongoDB* - ECC uses a MongoDB connection by default to query the session tokens provided on startup, and to securely provide startup information to requesting endpoints.
- *Golang* - For speed and efficiency, it's better that we use Golang to minimise intermediate latency between jumbled requests. Python would be too slow to maintain the efficacy of our infrastructure.


### Encryption & Data Security
ECC uses RSA asymmetric key encryption to maintain the security of tokens. When creating an instance, an RSA private key is provided back to the instance. **This will be the only time the private key will be able to be accessed, so ensure it is saved.**

A copy of the public key is saved on the server in the `./keys` directory. No use for public key storage has been determined at this point in the project.


