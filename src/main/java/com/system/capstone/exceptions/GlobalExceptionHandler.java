package com.system.capstone.exceptions;

import com.system.capstone.dto.ResponseDTO;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.validation.FieldError;

import java.util.stream.Collectors;

@ControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ResponseDTO<String>> handleValidationExceptions(MethodArgumentNotValidException ex) {
        // Get the list of all validation errors from the BindingResult
        String errorMessage = ex.getBindingResult().getAllErrors().stream()
                .map(objectError -> {
                    FieldError fieldError = (FieldError) objectError;
                    return fieldError.getField() + ": " + fieldError.getDefaultMessage();
                })
                .collect(Collectors.joining(", "));

        // Return the validation error messages in the response body
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(new ResponseDTO<>(errorMessage, HttpStatus.BAD_REQUEST, null));
    }
}
