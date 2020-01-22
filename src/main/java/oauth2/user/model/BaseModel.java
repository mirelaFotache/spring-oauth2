package oauth2.user.model;


import oauth2.user.listener.BaseEntityListener;
import org.hibernate.annotations.GenericGenerator;
import org.hibernate.annotations.Type;

import javax.persistence.*;
import java.io.Serializable;
import java.util.Date;
import java.util.UUID;

@MappedSuperclass
@EntityListeners(BaseEntityListener.class)
public abstract class BaseModel implements Serializable {

    @Id
    @GenericGenerator(name = "uuid2", strategy = "uuid2")
    @GeneratedValue(generator = "uuid2")
    @Type(type="uuid-char")
    @Column(name = "id", updatable = false, unique = true)
    private UUID id;

    @Temporal(TemporalType.TIMESTAMP)
    @Column(name = "date_created")
    @Type(type = "timestamp")
    private Date createdDate;

    @Temporal(TemporalType.TIMESTAMP)
    @Column(name = "date_update")
    @Type(type = "timestamp")
    private Date updateDate;

    @Column(name = "deleted")
    @Type(type = "boolean")
    private Boolean deleted = Boolean.FALSE;

    public BaseModel() {
        //Empty constructor
    }

    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id;
    }

    public Date getCreatedDate() {
        return createdDate;
    }

    public void setCreatedDate(Date createdDate) {
        this.createdDate = createdDate;
    }

    public Date getUpdateDate() {
        return updateDate;
    }

    public void setUpdateDate(Date updateDate) {
        this.updateDate = updateDate;
    }

    public Boolean getDeleted() {
        return deleted;
    }

    public void setDeleted(Boolean deleted) {
        this.deleted = deleted;
    }
}

