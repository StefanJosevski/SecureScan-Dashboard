package com.securescan.model;

public class Email {

    private String from;
    private String replyTo;
    private String subject;
    private String body;

    public Email(String from, String replyTo, String subject, String body) {
        this.from = from;
        this.replyTo = replyTo;
        this.subject = subject;
        this.body = body;
    }

    public String getFrom() {
        return from;
    }

    public String getReplyTo() {
        return replyTo;
    }

    public String getSubject() {
        return subject;
    }

    public String getBody() {
        return body;
    }
}
