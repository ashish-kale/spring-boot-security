package demo;

import java.util.ArrayList;
import java.util.HashMap;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class UserService implements UserDetailsService {
	
	 @Autowired
	 private HttpServletRequest request;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		
		String password = request.getParameter("password");
		
		if(checkKDB(username,password)) {
			return new User(username, password, new ArrayList<>());
		} else {
			throw new UsernameNotFoundException("User not found with login: " + username);
		}
	}
	
	private boolean checkKDB(String username,String password) {
		return true;
	}

}
