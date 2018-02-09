package ch.joebar.qos.mgr.web;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class Dump extends javax.servlet.http.HttpServlet implements javax.servlet.Servlet {
	private static final long serialVersionUID = 628677201596560405L;

	protected void doGet(HttpServletRequest request, HttpServletResponse response) {
		response.setContentType("text/html");
		ServletOutputStream out = null;
		try {
			out = response.getOutputStream();
			out.println("<html><title>GET</tile><body>");
			out.println("done");
			out.println("</body></html>");
			out.flush();
		} catch (IOException e) {
			// do nothing
		} finally {
			try {
				out.close();
			} catch (IOException e) {
				// do nothing
			}	
		}
	}
	
	protected void doPost(HttpServletRequest request, HttpServletResponse response)
		throws ServletException, IOException {
		this.doGet(request, response);
	}

}
