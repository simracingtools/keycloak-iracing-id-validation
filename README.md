# iRacing ID validation for Keycloak SSO

This project provides a form validation action that is able to check the existence of 
an iRacing customer ID contained in a user profile field for its existence in the iRacing
services utilizing the iRacing Data API (https://github.com/simracingtools/ir-data-api-client).

## Build

To build the provider jar for keycloak:

`
mvn clean package assembly:single
`

The so created jar contains all necessary dependencies.

## Deploy

Put the jar including dependencies in the `<keycloak-install-dir>/providers` directory.

If you do not have an own login theme in keycloak:

* Create a directory `<keycloak-install-dir>/themes/<my-theme-name>/login/messages`
* Copy the property files from `src/main/resources` into this directory
* Create a file `<keycloak-install-dir>/themes/<my-theme-name>/theme.properties` with the content `parent=keycloak`


If you already use a custom login theme in keycloak:

* Copy the property files from `src/main/resources` into your theme's messages directory

Finally, execute `<keycloak-install-dir>/kc.sh build` to activate the FormAction.

## Configure Keycloak

* Create a user profile attribute that will be used to contain the iRacing ID
* Follow the guide in https://www.keycloak.org/docs/latest/server_development/#adding-formaction-to-the-registration-flow to use the new 
"Signup IRacing ID Validation" form action in Keycloak registration flow.
* Configure the form action: provide your iRacing credentials and the name of the name of the 
user profile attribute which contains the iRacing id to check.

