
test:
	vendor/bin/atoum -d test;

dev-test:
	vendor/bin/atoum -d test -l;

phpcs:
	vendor/bin/phpcs --report=full --report-file=./report.txt --extensions=php --warning-severity=0 --standard=PSR2 -p ./src -p ./test;

phpcbf:
	vendor/bin/phpcbf --report=full --report-file=./report.txt --extensions=php --warning-severity=0 --standard=PSR2 -p ./src -p ./test;
