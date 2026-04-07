.PHONY: run test watch clean

run:
	python3 main.py --all

test:
	python3 -m unittest discover tests -v

watch:
	python3 main.py --watch logs/ssh.log

clean:
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -name "*.pyc" -delete
	rm -f output/report.json
	rm -f output/portscan_report.json