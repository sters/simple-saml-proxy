FROM kenchan0130/simplesamlphp:1.19.9

# Change Apache to listen on port 8001
RUN sed -i 's/Listen 8000/Listen 8001/g' /etc/apache2/ports.conf && \
    sed -i 's/:8000/:8001/g' /etc/apache2/sites-available/000-default.conf

EXPOSE 8001