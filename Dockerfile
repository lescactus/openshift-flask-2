FROM python:3.5-jessie

LABEL "Maintainer"="Alexandre Maldémé" \
        "version"="0.1"


# Add the app in /opt
ADD . /opt

# Working directory for "CMD"
WORKDIR /opt

# Set Flask env variables
ENV FLASK_APP=app.py \
    FLASK_DEBUG=1

# By default Flask use port 5000
EXPOSE 5000

RUN useradd --uid 100001 --gid 0 --shell /bin/bash -m test

# Install Flask via pip,
# Change ownership of app to www-data
RUN pip install -U pip && \
    pip install -r requirements.txt && \
    chown -R test: /opt

RUN chmod g+w /etc/passwd /etc

# "CMD" will be executed as www-data
USER test

ENTRYPOINT ["/opt/entrypoint.sh"]

# Run the app
CMD ["flask", "run", "--host=0.0.0.0"]
