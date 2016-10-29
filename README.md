# Bucketeer
This application is a bucket list sharing app where users can list what they want to do in life
before they "kick the bucket". Users can develop categories, called bucket lists with items in it.
The items represent what they want to do in life, composed of a title, description and 
an option to post image links. A user has to have a Facebook account or Google account to log in.
The site can also be viewed publicly wherein users that are not logged in can still view buckets shared by
users who have registered in the site.

The application is built with the Flask microwebframework, SQLite database with jinja2 templating.
The main files are project.py with database.py providing the model and catalog.db as the database itself.
The rest of the logic is contained in the jinja2 template folder files.

To run the application locally:
-------------------------------
1. Run 'python project.py'
2. Go to 'localhost:8000' on your web browser
3. Click the login link to login with facebook or google (must have those respective accounts)
4. Browse, you must add a category(bucket list) before you can add items
5. Here are the API endpoints with JSON responses :
		/showcategories/<int:user_id>/json - to get a list of categories by user
		/showitems/<int:category_id>/json - to get a list of items by category
		/showitem/<int:item_id>/json - to show a specific item's description
