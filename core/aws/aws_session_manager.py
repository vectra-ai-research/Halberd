import boto3
from botocore.exceptions import ClientError

class SessionManager:
    _sessions = {}  # Class variable to store sessions

    @classmethod
    def create_session(cls, name, **kwargs):
        """
        Create a new session with the given name and parameters.
        
        :param name: A unique identifier for this session
        :param kwargs: Arguments to pass to boto3.Session()
        """
        try:
            new_session = boto3.Session(**kwargs)
            # Verify the session is valid by calling STS
            sts = new_session.client('sts')
            sts.get_caller_identity()
            cls._sessions[name] = new_session
            
            return {"name" : name, "message" : "New session created"}
        except ClientError as e:
            return {"name" : name, "message" : "Failed to create session", "error" : str(e)}

    @classmethod
    def list_sessions(cls):
        """List all established sessions."""
        if not cls._sessions:
            return []
        else:
            sessions_list = []
            for name, session in cls._sessions.items():
                sessions_list.append(
                    {
                        "session_name" : name,
                        "region" : session.region_name,
                        "profile" : session.profile_name
                    }
                )
            return sessions_list

    @classmethod            
    def get_session(cls, name):
        """
        Retrieve a session by its name.
        
        :param name: The name of the session to retrieve
        :return: The requested boto3.Session object, or None if not found
        """
        session = cls._sessions.get(name)
        if session is None:
            return None
        return session
    
    @classmethod
    def set_default_session(cls, name):
        """
        Set a session as default session.This session is used across AWS techniques. 
        
        :param name: The name of the session to retrieve
        :return: The requested boto3.Session object, or None if not found
        """
        session = cls._sessions.get(name)
        if session is None:
            return {"error" : f"Session '{name}' not found."}
        else:
            boto3.DEFAULT_SESSION = cls._sessions[name]
            return {"success" : f"'{name}' session set as default AWS session."}

    def remove_session(cls, name):
        """
        Remove a session by its name.
        
        :param name: The name of the session to remove
        """
        if name in cls._sessions:
            del cls._sessions[name]
            return f"Session '{name}' removed."
        else:
            return f"Session '{name}' not found."