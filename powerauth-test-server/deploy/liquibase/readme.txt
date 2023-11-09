================================================================================
                          PowerAuth Test Server
                   Liquibase Setup Instructions
================================================================================

Directory Purpose:
------------------
The directory is dedicated to storing Liquibase scripts for Docker build context.

Setup Instructions:
-------------------
A) Manually copy all the contents from the following path:
   'docs/db/changelog/changesets/powerauth-test-server'
   to
   'powerauth-test-server/deploy/liquibase/data'

   - OR -

B) Utilize the 'copy_liquibase.sh' script available in the
   'powerauth-test-server' directory to automate the copying process.
================================================================================