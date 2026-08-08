# Installing Dopamine on a Corellium

1. Copy endpoint.sample.json to endpoint.json and add the credentials for the Corellium account, note that either username+password combination or a totp token is required
2. Compile Dopamine
3. Run `codesign -dvvvv on BaseBin/dopamine/dopamine`
4. Copy the CandidateCDHash and paste it into Settings -> Trust Cache on the Non-Jailbroken Corellium instance
5. Run `env NODE_TLS_REJECT_UNAUTHORIZED=0 node dopamine.js install <Project> <Instance>` where `Project` and `Instance` can either be a name or an ID
6. In the instance under "Port Forwarding", add a port: Device port = 22, Router port = 22, enable expose port
7. Ensure the device is connected to the Wi-Fi network
8. Under "Connect" you can find the Wi-Fi IP at the bottom
9. You can now SSH into the device using `ssh mobile@<Wi-Fi IP>`