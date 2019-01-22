git clone git@github.com:dancrew32/whodat.git whodat
cd whodat
make venv deps
./venv/bin/python /var/log/nginx/access.log
