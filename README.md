# cealr
Command line tool for sealing files with Cryptowerk API

### Building:
```console
$ mkdir -p build/debug
$ (cd build/debug && cmake ../..)
$ cmake --build build/debug
```

### Usage

#### Verifying a registered file
 
```console
$ ./cealr filetoseal.cpp

A file with the same hash as "filetoseal.cpp" has been registered with Cryptowerk 1 time(s).
Details:

```



User registration:

You need to have an account with cryptowerk.com to seal a file. One way to register is using the option --register with cealr 

Please dont use this option if you already have a cryptowerk account. It will delete the API key and API credential stored for your current user on your current system (~/.cealr/config.properties). 

```console
$ ./cealr --register
 
Please enter your email address..................: john.smith@maildomain.com
Please enter your first name.....................: John
Please enter your last name......................: Smith
Please enter your organization (if applicable)...: 
 
Contacting server for registration"http://localhost:8080/platform"
 
You are now registered with our server."http://localhost:8080/platform"
An email got send to your account "john.smith@maildomain.com.
Please find it and follow the instructions in this email to choose your password and
to activate your account.
After account activation you will be able to use the cealr command line tool to 
seal files for proof of existence.

```

Please look in your email account for the registration emil and follow the link to set your password. You will need this password for the first file that you want to seal.

Seal a file:

For sealing you need API Key and API Credential for your cryptowerk account. There are multiple ways to provide cealr with your api credentials.

As always for sealing you may just use option --seal if you just registered an account (e.g. with option --register) and you already set your password. Therefore it is necessary to find the email that the cryptowerk server sent to you and follow the registration URL. You wil need the password when you seal a file for the first time after registration.

```console
$ ./cealr --seal filetoseal.cpp

Please enter the password for your Cryptowerk account "john.smith@maildomain.com" 
 
File "filetoseal.cpp" is successfully registered with Cryptowerk.

```

This works only if you did not use your credentials already e.g. you are using the same account for sealing files on a second system or you can see your credentials one time in the portal if you are logged in there.
 

