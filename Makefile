test:
	vendor/bin/phpcs --report=full --report-file=./report.txt --extensions=php --warning-severity=0 --standard=PSR2 -p ./src;
	vendor/bin/phpstan analyse -l max src;
	vendor/bin/atoum -d tests;

dev-test:
	vendor/bin/atoum -d tests -l;

phpcs:
	vendor/bin/phpcs --report=full --report-file=./report.txt --extensions=php --warning-severity=0 --standard=PSR2 -p ./src -p ./test;

phpcbf:
	vendor/bin/phpcbf --report=full --report-file=./report.txt --extensions=php --warning-severity=0 --standard=PSR2 -p ./src -p ./test;
