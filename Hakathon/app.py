diff --git a/Hakathon/app.py b/Hakathon/app.py
--- a/Hakathon/app.py
+++ b/Hakathon/app.py
@@
 class Interest(db.Model):
     id = db.Column(db.Integer, primary_key=True)
     jobseekerid = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
     jobpostid = db.Column(db.Integer, db.ForeignKey("job_post.id"), nullable=False)
     approved = db.Column(db.Boolean, default=False)
+    chat_enabled = db.Column(db.Boolean, default=False)
     timestamp = db.Column(db.String(30))
@@
 def owner_chatroom(job_id):
@@
-    interests = Interest.query.filter_by(jobpostid=job_id).all()
+    interests = Interest.query.filter_by(jobpostid=job_id).all()
     applicants = []
     for rec in interests:
         seeker = User.query.get(rec.jobseekerid)
         if seeker:
             applicants.append({
                 "id": seeker.id,
                 "username": seeker.username,
                 "position": job.position,
                 "cv_link": url_for("view_seeker", seeker_id=seeker.id),
-                "chat_enabled": True,
+                "chat_enabled": rec.chat_enabled,
             })
@@
-    room = f"chat_{job_id}_{seeker_id}" if seeker_id else None
+    # Unified room id: chat_{owner_id}_{seeker_id}_{job_id}
+    room = f"chat_{owner.id}_{seeker_id}_{job_id}" if seeker_id else None
@@
-    if request.method == "POST" and "chat_action" in request.form:
-        action = request.form["chat_action"]
-        flash(f"Chat {action} for selected applicant.")
+    if request.method == "POST" and "chat_action" in request.form and seeker_id:
+        action = request.form["chat_action"]
+        interest = Interest.query.filter_by(jobpostid=job_id, jobseekerid=int(seeker_id)).first()
+        if interest:
+            if action == "enable":
+                interest.chat_enabled = True
+                db.session.commit()
+                flash("Chat enabled for this applicant.")
+            if action == "disable":
+                interest.chat_enabled = False
+                db.session.commit()
+                flash("Chat disabled for this applicant.")
@@
-    if request.method == "POST" and "text" in request.form and seeker_id:
+    if request.method == "POST" and "text" in request.form and seeker_id:
+        # Only allow sending if chat is enabled
+        interest = Interest.query.filter_by(jobpostid=job_id, jobseekerid=int(seeker_id)).first()
+        if not (interest and interest.chat_enabled):
+            flash("Chat not enabled for this applicant.")
+            return redirect(url_for("owner_chatroom", job_id=job_id, seeker_id=seeker_id))
         try:
             msg = Message(
                 owner_id=owner.id,
                 seeker_id=selected_seeker.id,
                 sender_id=owner.id,
                 content=request.form["text"],
                 timestamp=datetime.now().isoformat()
             )
             db.session.add(msg)
             db.session.commit()
             flash("Message sent.")
         except Exception as e:
             db.session.rollback()
             flash("Failed to send message.")
         return redirect(url_for("owner_chatroom", job_id=job_id, seeker_id=seeker_id))
@@
 @app.route("/seeker/chatroom/<int:job_id>")
 def seeker_chatroom(job_id):
     if not is_logged_in():
         return redirect(url_for("entry"))
     seeker = db.session.get(User, session["userid"])
     if seeker.role != "jobseeker":
         return redirect(url_for("entry"))
     job = JobPost.query.get_or_404(job_id)
     owner = User.query.get(job.ownerid)
     # Check chat enabled
     interest = Interest.query.filter_by(jobpostid=job_id, jobseekerid=seeker.id).first()
     chat_enabled = bool(interest and interest.chat_enabled)
     room = f"chat_{owner.id}_{seeker.id}_{job_id}"
     # Load messages
     chat_msgs = Message.query.filter_by(owner_id=owner.id, seeker_id=seeker.id).order_by(Message.timestamp).all()
     messages = [
         {"sendername": db.session.get(User, m.sender_id).username, "text": m.content, "timestamp": m.timestamp}
         for m in chat_msgs
     ]
     return render_template("chat_room.html", applicants=[], selected_seeker=None, messages=messages, room=room, user=seeker, chat_enabled=chat_enabled, owner=owner, job=job)
@@
 @socketio.on("send_message")
 def handle_message(data):
-    room = data["room"]
-    msg = data["msg"]
-    username = data["username"]
-    emit("receive_message", {"msg": msg, "username": username}, room=room)
+    room = data.get("room")
+    msg = data.get("msg", "")
+    username = data.get("username", "")
+    owner_id = data.get("owner_id")
+    seeker_id = data.get("seeker_id")
+    # Persist to DB if participants valid
+    try:
+        if owner_id and seeker_id and msg.strip():
+            message = Message(owner_id=int(owner_id), seeker_id=int(seeker_id), sender_id=db.session.get(User, session.get("userid")).id if session.get("userid") else int(owner_id), content=msg.strip(), timestamp=datetime.now().isoformat())
+            db.session.add(message)
+            db.session.commit()
+    except Exception:
+        db.session.rollback()
+    emit("receive_message", {"msg": msg, "username": username}, room=room)
