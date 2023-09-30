docker-compose build
docker-compose up

For quick check:
curl --header "Content-Type: application/json" \
  --request POST \
  --data '{"n":"2"}' \
  http://127.0.0.1:5000/process
