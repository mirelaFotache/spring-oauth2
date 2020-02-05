FROM openjdk:11-jdk
EXPOSE 8889
ADD /target/spring-oauth2-1.0-SNAPSHOT.jar spring-oauth2-1.0-SNAPSHOT.jar
ENTRYPOINT ["java","-jar","spring-oauth2-1.0-SNAPSHOT.jar"]