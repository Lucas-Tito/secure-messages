sudo docker-compose up --build
sudo docker-compose exec cliente python cliente.py "mensagem"
docker-compose logs -f servidor
sudo docker-compose logs -f servidor