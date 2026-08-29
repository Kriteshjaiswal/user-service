package com.aidocqa.user.kafka;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserEventProducer {

    private final KafkaTemplate<String, Object> kafkaTemplate;

    public static final String TOPIC_USER_CREATED = "user.events.created";
    public static final String TOPIC_USER_VERIFIED = "user.events.verified";
    public static final String TOPIC_SESSION_EXPIRED = "user.events.session.expired";
    public static final String TOPIC_USER_DELETED = "user.events.deleted";
    public static final String TOPIC_EMAIL_OTP = "notification.email.otp";

    public void publishUserCreated(UserCreatedEvent event) {
        publishEvent(TOPIC_USER_CREATED, String.valueOf(event.getUserId()), event);
    }

    public void publishUserVerified(UserVerifiedEvent event) {
        publishEvent(TOPIC_USER_VERIFIED, String.valueOf(event.getUserId()), event);
    }

    public void publishSessionExpired(SessionExpiredEvent event) {
        publishEvent(TOPIC_SESSION_EXPIRED, event.getSessionId(), event);
    }

    public void publishUserDeleted(UserDeletedEvent event) {
        publishEvent(TOPIC_USER_DELETED, String.valueOf(event.getUserId()), event);
    }

    public void publishEmailOtp(EmailOtpEvent event) {
        publishEvent(TOPIC_EMAIL_OTP, event.getRecipientEmail(), event);
    }

    private void publishEvent(String topic, String key, Object payload) {
        try {
            if (kafkaTemplate != null) {
                kafkaTemplate.send(topic, key, payload)
                        .whenComplete((result, ex) -> {
                            if (ex != null) {
                                log.warn("Failed to publish Kafka event to topic '{}': {}", topic, ex.getMessage());
                            } else {
                                log.info("Successfully published Kafka event to topic '{}' with key '{}'", topic, key);
                            }
                        });
            }
        } catch (Exception e) {
            log.warn("Kafka not reachable or disabled for topic '{}': {}", topic, e.getMessage());
        }
    }
}
