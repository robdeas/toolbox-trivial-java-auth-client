plugins {
    id("org.springframework.boot") version "3.4.2"
    id("io.spring.dependency-management") version "1.1.7"
    java
}

group = "tech.robd.toolbox.trivialauth.client"
version = "0.0.1-SNAPSHOT"
java {
    sourceCompatibility = JavaVersion.VERSION_21
    targetCompatibility = JavaVersion.VERSION_21
}

repositories {
    mavenCentral()
}

dependencies {
    implementation("org.springframework.boot:spring-boot-starter-web")
    implementation("org.springframework.boot:spring-boot-starter-thymeleaf")
    implementation("org.springframework.boot:spring-boot-starter-security")
    // only required if JWT bearer token access is required for REST APIS (rather than logging in and using the Spring session)
    implementation("org.springframework.boot:spring-boot-starter-oauth2-resource-server")
    // used for the reading of the JWT auth microservice API
    implementation("io.jsonwebtoken:jjwt-api:0.11.5")
    runtimeOnly("io.jsonwebtoken:jjwt-impl:0.11.5")
    runtimeOnly("io.jsonwebtoken:jjwt-jackson:0.11.5")
    testImplementation("org.springframework.security:spring-security-test")
    testImplementation("org.springframework.boot:spring-boot-starter-test")
}

tasks.withType<Test> {
    useJUnitPlatform()
}

tasks.test {
    doFirst {
        val byteBuddyAgentJar = configurations.testRuntimeClasspath.get().files
            .find { it.name.contains("byte-buddy-agent") }
        if (byteBuddyAgentJar != null) {
            jvmArgs("-javaagent:${byteBuddyAgentJar.absolutePath}")
        }
    }
}

