package org.kx;

import java.io.IOException;

import jakarta.servlet.ServletException;
import jakarta.servlet.ServletResponse;

@FunctionalInterface
public interface KxRequestRunner {

    void run(KxCryptoRequestWrapper request, ServletResponse response) throws IOException, ServletException;
}
