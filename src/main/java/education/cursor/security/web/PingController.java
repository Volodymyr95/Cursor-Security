package education.cursor.security.web;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(value = "/api/ping")
public class PingController {

    @GetMapping
    public String ping() {
        return "ping";
    }

}
