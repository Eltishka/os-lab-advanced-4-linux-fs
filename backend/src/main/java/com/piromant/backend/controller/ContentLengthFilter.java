package com.piromant.backend.controller;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletResponseWrapper;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.util.ContentCachingResponseWrapper;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintWriter;

// Самый высокий приоритет
@Component
public class ContentLengthFilter implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response,
                         FilterChain chain) throws IOException, ServletException {

        if (response instanceof HttpServletResponse) {
            ContentCachingResponseWrapper responseWrapper =
                    new ContentCachingResponseWrapper((HttpServletResponse) response);

            try {
                chain.doFilter(request, responseWrapper);
            } finally {
                // Автоматически вычисляет Content-Length
                responseWrapper.copyBodyToResponse();
            }
        } else {
            chain.doFilter(request, response);
        }
    }

    private static class ContentLengthResponseWrapper extends HttpServletResponseWrapper {
        private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        private ServletOutputStream servletOutputStream;
        private PrintWriter printWriter;
        private int contentLength = 0;

        public ContentLengthResponseWrapper(HttpServletResponse response) {
            super(response);
        }

        @Override
        public ServletOutputStream getOutputStream() {
            if (servletOutputStream == null) {
                servletOutputStream = new ServletOutputStream() {
                    @Override
                    public void write(int b) throws IOException {
                        buffer.write(b);
                        contentLength++;
                        if (contentLength > 0) {
                            getResponse().setContentLength(contentLength);
                        }
                    }

                    @Override
                    public void write(byte[] b, int off, int len) throws IOException {
                        buffer.write(b, off, len);
                        contentLength += len;
                        if (contentLength > 0) {
                            getResponse().setContentLength(contentLength);
                        }
                    }

                    @Override
                    public boolean isReady() {
                        return true;
                    }

                    @Override
                    public void setWriteListener(WriteListener listener) {
                    }
                };
            }
            return servletOutputStream;
        }

        @Override
        public PrintWriter getWriter() throws IOException {
            if (printWriter == null) {
                printWriter = new PrintWriter(getOutputStream(), true);
            }
            return printWriter;
        }

        @Override
        public void flushBuffer() throws IOException {
            if (printWriter != null) {
                printWriter.flush();
            }
            if (servletOutputStream != null) {
                servletOutputStream.flush();
            }

            // Записываем данные в оригинальный response
            byte[] data = buffer.toByteArray();
            getResponse().setContentLength(data.length);
            getResponse().getOutputStream().write(data);
            getResponse().getOutputStream().flush();
        }
    }
}