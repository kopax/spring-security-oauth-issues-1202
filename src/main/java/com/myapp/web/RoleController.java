package com.myapp.web;

import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * RoleController used to serve Role data
 */
@RestController
@RequestMapping("/roles")
@PreAuthorize("hasAnyAuthority('ROLE_USER')")
public class RoleController {

    @GetMapping(produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> userOrganizationAuthorityList() {
        return ResponseEntity.ok(true);
    }

}
