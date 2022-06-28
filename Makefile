test:
	vendor/bin/phpcs --report=full --report-file=./report.txt -p ./src;
	vendor/bin/phpstan analyse -c phpstan.neon;
	vendor/bin/atoum -d tests;

dev-test:
	vendor/bin/atoum -d tests -l;

phpcs:
	vendor/bin/phpcs --report=full --report-file=./report.txt -p ./src;

phpcbf:
	vendor/bin/phpcbf -p ./src;
