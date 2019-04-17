package vn.edu.leading.uaa.repositories;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import vn.edu.leading.uaa.models.RoleModel;

import java.util.List;

@Repository
public interface RoleRepository extends JpaRepository<RoleModel, Long> {

    List<RoleModel> findByNameContaining(String term);

    RoleModel findByName(String s);

}
