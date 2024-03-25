build:
	@echo Building instances
	@docker-compose -f docker-compose.dev.yml build

start: build
	@echo Starting instances
	@docker-compose -f docker-compose.dev.yml up -d

stop:
	@echo Shutting down instances
	@docker-compose down

status:
	@echo Checking application status
	@docker ps -a

test:
	@echo Runing tests
	@docker-compose exec web python manage.py test